package v1alpha1

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/tidwall/gjson"
	"github.com/tratteria/tratteria-agent/common"
	"github.com/tratteria/tratteria-agent/trat"
)

type VerificationRulesManager interface {
	AddTraTRule(VerificationTraTRule) error
	UpdateTratteriaConfigRule(VerificationTratteriaConfigRule)
	UpdateCompleteRules(VerificationRulesTconfigd) error
	GetRulesJSON() (json.RawMessage, error)
}

type VerificationRulesApplier interface {
	ApplyRule(trat *trat.TraT, path string, method common.HttpMethod, input map[string]interface{}) (bool, string, error)
}

type VerificationTratteriaConfigRule struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
}

type VerificationTraTRule struct {
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

type VerificationTraTRules map[common.HttpMethod]map[string]VerificationTraTRule

type VerificationRules struct {
	TratteriaConfigRules *VerificationTratteriaConfigRule `json:"tratteriaConfigRules"`
	TraTRules            VerificationTraTRules            `json:"traTRules"`
}

func NewVerificationRules() *VerificationRules {
	traTRules := make(VerificationTraTRules)

	for _, method := range common.HttpMethodList {
		traTRules[method] = make(map[string]VerificationTraTRule)
	}

	return &VerificationRules{
		TratteriaConfigRules: &VerificationTratteriaConfigRule{},
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

func (vri *VerificationRulesImp) AddTraTRule(verificationtraTRule VerificationTraTRule) error {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	if _, exist := vri.rules.TraTRules[verificationtraTRule.Method]; !exist {
		return fmt.Errorf("invalid HTTP method: %s", string(verificationtraTRule.Method))
	}

	vri.rules.TraTRules[verificationtraTRule.Method][verificationtraTRule.Endpoint] = verificationtraTRule

	return nil
}

func (vri *VerificationRulesImp) UpdateTratteriaConfigRule(tratteriaConfigRule VerificationTratteriaConfigRule) {
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
func (vri *VerificationRulesImp) matchRule(path string, method common.HttpMethod) (VerificationTraTRule, map[string]string, error) {
	methodRuleMap, ok := vri.rules.TraTRules[method]
	if !ok {
		return VerificationTraTRule{}, nil, fmt.Errorf("invalid HTTP method: %s", string(method))
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

	return VerificationTraTRule{}, nil, errors.New("no matching rule found")
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

type VerificationRulesTconfigd struct {
	VerificationTratteriaConfigRule *VerificationTratteriaConfigRule `json:"verificationTratteriaConfigRule"`
	VerificationTraTRules           []*VerificationTraTRule          `json:"verificationTraTRules"`
}

func (vri *VerificationRulesImp) UpdateCompleteRules(verificationRulesTconfigd VerificationRulesTconfigd) error {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	vri.rules.TratteriaConfigRules = verificationRulesTconfigd.VerificationTratteriaConfigRule

	traTRules := make(VerificationTraTRules)

	for _, method := range common.HttpMethodList {
		traTRules[method] = make(map[string]VerificationTraTRule)
	}

	for _, endpointRule := range verificationRulesTconfigd.VerificationTraTRules {
		traTRules[endpointRule.Method][endpointRule.Endpoint] = *endpointRule
	}

	vri.rules.TraTRules = traTRules

	return nil
}
