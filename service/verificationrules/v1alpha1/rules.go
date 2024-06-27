package v1alpha1

import (
	"sync"
)

type VerificationRulesManager interface {
	AddRule(rule VerificationRule)
	GetRules() map[string]map[string]VerificationRule
	GetRulesVersionId() string
}

type VerificationRulesMatcher interface {
	MatchRule(path string, method string) (VerificationRule, map[string]string, error)
}

type VerificationRule struct {
	Endpoint   string     `json:"endpoint"`
	Method     string     `json:"method"`
	Purp       string     `json:"purp"`
	AzdMapping AzdMapping `json:"azdmapping,omitempty"`
}

type AzdMapping map[string]AzdField
type AzdField struct {
	Required bool   `json:"required"`
	Value    string `json:"value"`
}

type VerificationRules struct {
	rules          map[string]map[string]VerificationRule
	rulesVersionId string
	mu             sync.RWMutex
}

func NewVerificationRules() *VerificationRules {
	return &VerificationRules{
		rules: make(map[string]map[string]VerificationRule),
	}
}

func (m *VerificationRules) AddRule(rule VerificationRule) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exist := m.rules[rule.Method]; !exist {
		m.rules[rule.Method] = make(map[string]VerificationRule)
	}

	m.rules[rule.Method][rule.Endpoint] = rule
}

func (m *VerificationRules) GetRules() map[string]map[string]VerificationRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.rules
}

func (m *VerificationRules) MatchRule(path string, method string) (VerificationRule, map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// TODO: match and extract variables
	return VerificationRule{}, nil, nil
}

func (m *VerificationRules) GetRulesVersionId() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.rulesVersionId
}
