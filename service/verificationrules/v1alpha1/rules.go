package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
	"github.com/tratteria/tratteria-agent/common"
	"github.com/tratteria/tratteria-agent/trat"
	"github.com/tratteria/tratteria-agent/utils"
)

type VerificationRulesManager interface {
	AddTraTRule(TraTVerificationRule) error
	UpdateTratteriaConfigRule(TratteriaConfigVerificationRule)
	UpdateCompleteRules(*TconfigdVerificationRules)
	GetRulesJSON() (json.RawMessage, error)
	GetVerificationRulesHash() (string, error)
}

type VerificationRulesApplier interface {
	ApplyRule(trat *trat.TraT, path string, method common.HttpMethod, input map[string]interface{}) (bool, string, error)
}

type TratteriaConfigVerificationRule struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
}

type TraTVerificationRule struct {
	Endpoint   string            `json:"endpoint"`
	Method     common.HttpMethod `json:"method"`
	Purp       string            `json:"purp"`
	AzdMapping AzdMapping        `json:"azdmapping,omitempty"`
}

type AzdMapping map[string]AzdField
type AzdField struct {
	Required bool   `json:"required"`
	Value    string `json:"value"`
}

type TraTVerificationRules map[common.HttpMethod]map[string]TraTVerificationRule

type VerificationRules struct {
	TratteriaConfigRules *TratteriaConfigVerificationRule `json:"tratteriaConfigRules"`
	TraTRules            TraTVerificationRules            `json:"traTRules"`
}

func NewVerificationRules() *VerificationRules {
	traTRules := make(TraTVerificationRules)

	for _, method := range common.HttpMethodList {
		traTRules[method] = make(map[string]TraTVerificationRule)
	}

	return &VerificationRules{
		TratteriaConfigRules: &TratteriaConfigVerificationRule{},
		TraTRules:            traTRules,
	}
}

type VerificationRulesImp struct {
	rules *VerificationRules
	mu    sync.RWMutex
}

func NewVerificationRulesImp() *VerificationRulesImp {
	return &VerificationRulesImp{
		rules: NewVerificationRules(),
	}
}

func (vri *VerificationRulesImp) AddTraTRule(verificationtraTRule TraTVerificationRule) error {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	if _, exist := vri.rules.TraTRules[verificationtraTRule.Method]; !exist {
		return fmt.Errorf("invalid HTTP method: %s", string(verificationtraTRule.Method))
	}

	vri.rules.TraTRules[verificationtraTRule.Method][verificationtraTRule.Endpoint] = verificationtraTRule

	return nil
}

func (vri *VerificationRulesImp) UpdateTratteriaConfigRule(tratteriaConfigRule TratteriaConfigVerificationRule) {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	vri.rules.TratteriaConfigRules = &tratteriaConfigRule
}

func (vri *VerificationRulesImp) GetRulesJSON() (json.RawMessage, error) {
	vri.mu.RLock()
	defer vri.mu.RUnlock()

	jsonData, err := json.Marshal(vri.rules)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// Read lock should be take by the function calling matchRule.
func (vri *VerificationRulesImp) matchRule(path string, method common.HttpMethod) (TraTVerificationRule, map[string]string, error) {
	methodRuleMap, ok := vri.rules.TraTRules[method]
	if !ok {
		return TraTVerificationRule{}, nil, fmt.Errorf("invalid HTTP method: %s", string(method))
	}

	for pattern, rule := range methodRuleMap {
		regexPattern := convertToRegex(pattern)
		re := regexp.MustCompile(regexPattern)

		if re.MatchString(path) {
			matches := re.FindStringSubmatch(path)
			names := re.SubexpNames()

			pathParameters := make(map[string]string)

			for i, name := range names {
				if i != 0 && name != "" {
					pathParameters[name] = matches[i]
				}
			}

			return rule, pathParameters, nil
		}
	}

	return TraTVerificationRule{}, nil, errors.New("no matching rule found")
}

func convertToRegex(template string) string {
	r := strings.NewReplacer("{#", "(?P<", "}", ">[^/]+)")

	return "^" + r.Replace(template) + "$"
}

func (vri *VerificationRulesImp) ApplyRule(trat *trat.TraT, path string, method common.HttpMethod, input map[string]interface{}) (bool, string, error) {
	vri.mu.RLock()
	defer vri.mu.RUnlock()

	if vri.rules.TratteriaConfigRules.Issuer != trat.Issuer {
		return false, "invalid issuer", nil
	}

	if vri.rules.TratteriaConfigRules.Audience != trat.Audience {
		return false, "invalid audience", nil
	}

	traTRule, pathParameter, err := vri.matchRule(path, method)
	if err != nil {
		return false, fmt.Sprintf("trat verification rule not found for %s path and %s method", path, method), err
	}

	if traTRule.Purp != trat.Purp {
		return false, "invalid purp", nil
	}

	for par, val := range pathParameter {
		input[par] = val
	}

	if traTRule.AzdMapping == nil && trat.Azd == nil {
		return true, "", nil
	}

	valid, err := vri.validateAzd(traTRule.AzdMapping, input, trat)
	if err != nil {
		return false, "", err
	} else {
		if !valid {
			return false, "invalid azd", nil
		}

		return valid, "", nil
	}
}

func (vri *VerificationRulesImp) validateAzd(azdMapping AzdMapping, input map[string]interface{}, trat *trat.TraT) (bool, error) {
	jsonInput, err := marshalToJson(input)
	if err != nil {
		return false, fmt.Errorf("failed to marshal %v input to JSON: %w", input, err)
	}

	for key, azdField := range azdMapping {
		valueSpec := azdField.Value

		var value interface{}

		if strings.HasPrefix(valueSpec, "${") && strings.HasSuffix(valueSpec, "}") {
			path := strings.TrimSuffix(strings.TrimPrefix(valueSpec, "${"), "}")
			value = extractValueFromJson(jsonInput, path)
		} else {
			value = valueSpec
		}

		tratValue := trat.Azd[key]

		if !azdField.Required {
			if value == nil && tratValue == nil {
				return true, nil
			}

			if !(value != nil && tratValue != nil) {
				return false, nil
			}
		}

		if !compareJSONClaims(value, tratValue) {
			return false, nil
		}
	}

	return true, nil
}

func compareJSONClaims(a, b interface{}) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}

	jsonA, errA := json.Marshal(a)
	jsonB, errB := json.Marshal(b)

	if errA != nil || errB != nil {
		return false
	}

	var objA, objB interface{}

	if err := json.Unmarshal(jsonA, &objA); err != nil {
		return false
	}

	if err := json.Unmarshal(jsonB, &objB); err != nil {
		return false
	}

	return reflect.DeepEqual(objA, objB)
}

func extractValueFromJson(jsonStr string, path string) interface{} {
	result := gjson.Get(jsonStr, path)

	if result.Exists() {
		return result.Value()
	}

	return nil
}

func marshalToJson(data map[string]interface{}) (string, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

type TconfigdVerificationRules struct {
	TratteriaConfigVerificationRule *TratteriaConfigVerificationRule `json:"tratteriaConfigVerificationRule"`
	TraTVerificationRules           []*TraTVerificationRule          `json:"traTVerificationRules"`
}

func (vri *VerificationRulesImp) UpdateCompleteRules(tconfigdVerificationRules *TconfigdVerificationRules) {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	vri.rules.TratteriaConfigRules = tconfigdVerificationRules.TratteriaConfigVerificationRule

	traTRules := make(TraTVerificationRules)

	for _, method := range common.HttpMethodList {
		traTRules[method] = make(map[string]TraTVerificationRule)
	}

	for _, endpointRule := range tconfigdVerificationRules.TraTVerificationRules {
		traTRules[endpointRule.Method][endpointRule.Endpoint] = *endpointRule
	}

	vri.rules.TraTRules = traTRules
}

func (tconfigdVerificationRules *TconfigdVerificationRules) ComputeStableHash() (string, error) {
	var sortErr error

	sort.SliceStable(tconfigdVerificationRules.TraTVerificationRules, func(i, j int) bool {
		if sortErr != nil {
			return false
		}

		iJSON, err := json.Marshal(tconfigdVerificationRules.TraTVerificationRules[i])
		if err != nil {
			sortErr = fmt.Errorf("failed to marshal rule %d: %w", i, err)

			return false
		}

		jJSON, err := json.Marshal(tconfigdVerificationRules.TraTVerificationRules[j])
		if err != nil {
			sortErr = fmt.Errorf("failed to marshal rule %d: %w", j, err)

			return false
		}

		iStr, err := utils.CanonicalizeJSON(json.RawMessage(iJSON))
		if err != nil {
			sortErr = fmt.Errorf("failed to canonicalize rule %d: %w", i, err)

			return false
		}

		jStr, err := utils.CanonicalizeJSON(json.RawMessage(jJSON))
		if err != nil {
			sortErr = fmt.Errorf("failed to canonicalize rule %d: %w", j, err)

			return false
		}

		return iStr < jStr
	})

	if sortErr != nil {
		return "", fmt.Errorf("error during sorting: %w", sortErr)
	}

	data, err := json.Marshal(tconfigdVerificationRules)
	if err != nil {
		return "", fmt.Errorf("failed to marshal rules: %w", err)
	}

	var jsonData interface{}

	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal for canonicalization: %w", err)
	}

	canonicalizedData, err := utils.CanonicalizeJSON(jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize JSON: %w", err)
	}

	hash := sha256.Sum256([]byte(canonicalizedData))

	return hex.EncodeToString(hash[:]), nil
}

func (vri *VerificationRulesImp) GetVerificationRulesHash() (string, error) {
	vri.mu.RLock()
	defer vri.mu.RUnlock()

	var tconfigdVerificationRules TconfigdVerificationRules

	tconfigdVerificationRules.TratteriaConfigVerificationRule = vri.rules.TratteriaConfigRules

	var traTVerificationRules []*TraTVerificationRule

	for _, methodRules := range vri.rules.TraTRules {
		for _, endpointRule := range methodRules {
			ruleCopy := endpointRule
			traTVerificationRules = append(traTVerificationRules, &ruleCopy)
		}
	}

	tconfigdVerificationRules.TraTVerificationRules = traTVerificationRules

	return tconfigdVerificationRules.ComputeStableHash()
}
