package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/tratteria/tratteria-agent/tratverificationreasons"
	"github.com/tratteria/tratteria-agent/utils"
)

type VerificationRulesManager interface {
	UpsertTraTRule(*ServiceTraTVerificationRules) error
	UpdateTratteriaConfigRule(*TratteriaConfigVerificationRule)
	UpdateCompleteRules(*VerificationRules)
	GetRulesJSON() (json.RawMessage, error)
	GetVerificationRulesHash() (string, error)
	DeleteTrat(string)
	UpsertTraTExclRule(traTExclRule *TraTExclRule) error
	DeleteTratExcl()
}

type VerificationRulesApplier interface {
	ApplyRule(trat *trat.TraT, path string, method common.HttpMethod, input map[string]interface{}) (bool, string, error)
	IsTraTExcluded(path string, method common.HttpMethod) (bool, error)
}

type TratteriaConfigVerificationRule struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
}

type TraTVerificationRule struct {
	TraTName   string            `json:"traTName"`
	Endpoint   string            `json:"endpoint"`
	Method     common.HttpMethod `json:"method"`
	Purp       string            `json:"purp"`
	AzdMapping AzdMapping        `json:"azdmapping,omitempty"`
}

type ServiceTraTVerificationRules struct {
	TraTName              string
	TraTVerificationRules []*TraTVerificationRule
}

type AzdMapping map[string]AzdField
type AzdField struct {
	Required bool   `json:"required"`
	Value    string `json:"value"`
}

type TraTExclRule struct {
	Endpoints []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	Path   string            `json:"path"`
	Method common.HttpMethod `json:"method"`
}

type VerificationRules struct {
	TratteriaConfigVerificationRule *TratteriaConfigVerificationRule         `json:"tratteriaConfigVerificationRule"`
	TraTsVerificationRules          map[string]*ServiceTraTVerificationRules `json:"traTsVerificationRules"`
	TraTExclRule                    *TraTExclRule                            `json:"traTExclRule"`
}

func NewVerificationRules() *VerificationRules {
	return &VerificationRules{
		TraTsVerificationRules: make(map[string]*ServiceTraTVerificationRules),
	}
}

type IndexedTraTsVerificationRules map[common.HttpMethod]map[string]*EndpointRule

type EndpointRule struct {
	Skip  bool
	Rules []*TraTVerificationRule
}

type VerificationRulesImp struct {
	verificationRules             *VerificationRules
	indexedTraTsVerificationRules IndexedTraTsVerificationRules
	mu                            sync.RWMutex
}

func NewVerificationRulesImp() *VerificationRulesImp {
	indexedTraTsVerificationRules := make(IndexedTraTsVerificationRules)

	for _, method := range common.HttpMethodList {
		indexedTraTsVerificationRules[method] = make(map[string]*EndpointRule)
	}

	return &VerificationRulesImp{
		verificationRules:             NewVerificationRules(),
		indexedTraTsVerificationRules: indexedTraTsVerificationRules,
	}
}

func (vri *VerificationRulesImp) UpsertTraTRule(serviceTraTVerificationRules *ServiceTraTVerificationRules) error {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	for _, traTVerificationRule := range serviceTraTVerificationRules.TraTVerificationRules {
		if _, exist := vri.indexedTraTsVerificationRules[traTVerificationRule.Method]; !exist {
			return fmt.Errorf("invalid HTTP method %s for %s trat", string(traTVerificationRule.Method), traTVerificationRule.TraTName)
		}
	}

	vri.verificationRules.TraTsVerificationRules[serviceTraTVerificationRules.TraTName] = serviceTraTVerificationRules

	vri.indexTraTsVerificationRules()

	return nil
}

func (vri *VerificationRulesImp) UpsertTraTExclRule(traTExclRule *TraTExclRule) error {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	for _, traTExclEndpoint := range traTExclRule.Endpoints {
		if _, exist := vri.indexedTraTsVerificationRules[traTExclEndpoint.Method]; !exist {
			return fmt.Errorf("invalid HTTP method %s for %s path in tratexcl rule", string(traTExclEndpoint.Method), traTExclEndpoint.Path)
		}
	}

	vri.verificationRules.TraTExclRule = traTExclRule

	vri.indexTraTsVerificationRules()

	return nil
}

func (vri *VerificationRulesImp) DeleteTrat(tratName string) {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	delete(vri.verificationRules.TraTsVerificationRules, tratName)

	vri.indexTraTsVerificationRules()
}

func (vri *VerificationRulesImp) DeleteTratExcl() {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	vri.verificationRules.TraTExclRule = nil

	vri.indexTraTsVerificationRules()
}

// write lock should be taken my method calling indexTraTsGenerationRules.
func (vri *VerificationRulesImp) indexTraTsVerificationRules() {
	indexedRules := make(IndexedTraTsVerificationRules)

	for _, method := range common.HttpMethodList {
		indexedRules[method] = make(map[string]*EndpointRule)
	}

	if vri.verificationRules != nil && vri.verificationRules.TraTsVerificationRules != nil {
		for _, serviceRules := range vri.verificationRules.TraTsVerificationRules {
			for _, rule := range serviceRules.TraTVerificationRules {
				if indexedRules[rule.Method][rule.Endpoint] == nil {
					indexedRules[rule.Method][rule.Endpoint] = &EndpointRule{Skip: false}
				}

				indexedRules[rule.Method][rule.Endpoint].Rules = append(
					indexedRules[rule.Method][rule.Endpoint].Rules, rule)
			}
		}
	}

	// Index exclusion rules
	if vri.verificationRules.TraTExclRule != nil {
		for _, endpoint := range vri.verificationRules.TraTExclRule.Endpoints {
			if indexedRules[endpoint.Method][endpoint.Path] == nil {
				indexedRules[endpoint.Method][endpoint.Path] = &EndpointRule{}
			}

			indexedRules[endpoint.Method][endpoint.Path].Skip = true
			indexedRules[endpoint.Method][endpoint.Path].Rules = nil // Clear any existing rules
		}
	}

	vri.indexedTraTsVerificationRules = indexedRules
}

func (vri *VerificationRulesImp) UpdateTratteriaConfigRule(tratteriaConfigRule *TratteriaConfigVerificationRule) {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	vri.verificationRules.TratteriaConfigVerificationRule = tratteriaConfigRule
}

func (vri *VerificationRulesImp) GetRulesJSON() (json.RawMessage, error) {
	vri.mu.RLock()
	defer vri.mu.RUnlock()

	jsonData, err := json.Marshal(vri.verificationRules)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// Read lock should be take by the function calling matchRule.
func (vri *VerificationRulesImp) matchRule(path string, method common.HttpMethod) (*EndpointRule, map[string]string, error) {
	methodRuleMap, ok := vri.indexedTraTsVerificationRules[method]
	if !ok {
		return nil, nil, fmt.Errorf("invalid HTTP method: %s", string(method))
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

	return nil, nil, errors.New("no matching rule found")
}

func convertToRegex(template string) string {
	r := strings.NewReplacer("{#", "(?P<", "}", ">[^/]+)")

	return "^" + r.Replace(template) + "$"
}

func (vri *VerificationRulesImp) ApplyRule(trat *trat.TraT, path string, method common.HttpMethod, input map[string]interface{}) (bool, string, error) {
	vri.mu.RLock()
	defer vri.mu.RUnlock()

	if vri.verificationRules.TratteriaConfigVerificationRule == nil {
		return false, "", fmt.Errorf("tratteria config verification rule not set")
	}

	if vri.verificationRules.TratteriaConfigVerificationRule.Issuer != trat.Issuer {
		return false, tratverificationreasons.InvalidIssuer, nil
	}

	if vri.verificationRules.TratteriaConfigVerificationRule.Audience != trat.Audience {
		return false, tratverificationreasons.InvalidAudience, nil
	}

	endpointRule, pathParameter, err := vri.matchRule(path, method)
	if err != nil {
		return false, fmt.Sprintf(tratverificationreasons.VerificationRuleNotFound, path, method), err
	}

	if endpointRule.Skip {
		return true, tratverificationreasons.VerificationSkipped, nil
	}

	for _, traTRule := range endpointRule.Rules {
		if traTRule.Purp != trat.Purp {
			continue
		}

		for par, val := range pathParameter {
			input[par] = val
		}

		if traTRule.AzdMapping == nil && trat.Azd == nil {
			return true, "", nil
		}

		valid, err := vri.validateAzd(traTRule.AzdMapping, input, trat)
		if err != nil {
			continue
		} else {
			if !valid {
				continue
			}

			return valid, "", nil
		}
	}

	return false, tratverificationreasons.InvalidAuthDetails, err
}

func (vri *VerificationRulesImp) IsTraTExcluded(path string, method common.HttpMethod) (bool, error) {
	vri.mu.RLock()
	defer vri.mu.RUnlock()

	methodRuleMap, ok := vri.indexedTraTsVerificationRules[method]
	if !ok {
		return false, fmt.Errorf("invalid HTTP method: %s", string(method))
	}

	for pattern, rule := range methodRuleMap {
		regexPattern := convertToRegex(pattern)
		re := regexp.MustCompile(regexPattern)

		if re.MatchString(path) {
			return rule.Skip, nil
		}
	}

	return false, nil // If no rule is found, it is not excluded
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

func (vri *VerificationRulesImp) UpdateCompleteRules(verificationRules *VerificationRules) {
	vri.mu.Lock()
	defer vri.mu.Unlock()

	vri.verificationRules = verificationRules

	vri.indexTraTsVerificationRules()
}

func (verificationRules *VerificationRules) ComputeStableHash() (string, error) {
	data, err := json.Marshal(verificationRules)
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

	return vri.verificationRules.ComputeStableHash()
}
