package tratverifier

import (
	"net/http"

	"github.com/tratteria/tratteria-agent/tratteriatrustbundlemanager"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
)

type TraTVerifier struct {
	verificationRulesMatcher    v1alpha1.VerificationRulesMatcher
	tratteriaTrustBundleManager *tratteriatrustbundlemanager.TratteriaTrustBundleManager
}

func NewTraTVerifier(verificationRulesAccesser v1alpha1.VerificationRulesMatcher, tratteriaTrustBundleManager *tratteriatrustbundlemanager.TratteriaTrustBundleManager) *TraTVerifier {
	return &TraTVerifier{
		verificationRulesMatcher:    verificationRulesAccesser,
		tratteriaTrustBundleManager: tratteriaTrustBundleManager,
	}
}

func (tv *TraTVerifier) VerifyTraT(path string, method string, queryParameters map[string]string, headers http.Header, body string) bool {
	// TODO: match rule, verify signature, and verify trat body.
	// TODO: log all verification failuers
	return true
}
