package rules

type VerificationRule struct {
	Type    string `json:"type"`
	Service string `json:"service"`
	Route   string `json:"route"`
	Method  string `json:"method"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	TraTName   string                          `json:"traT-name"`
	AdzMapping map[string]VerificationAdzField `json:"adz-mapping"`
}

type VerificationAdzField struct {
	Path     string `json:"path"`
	Required bool   `json:"required"`
}

type Rules struct {
	verificationRules map[string]VerificationRule
}

func NewRules() *Rules {
	return &Rules{
		verificationRules: make(map[string]VerificationRule),
	}
}

func (r *Rules) Apply() error {
	// TODO
	return nil
}

func (r *Rules) Verify() (bool, error) {
	// TODO
	return true, nil
}

func (r *Rules) GetRulesVersionID() string {
	// TODO
	return ""
}

func (r *Rules) GetVerificationRule() map[string]VerificationRule {
	return r.verificationRules
}
