package service

import (
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

type Service struct {
	verificationRulesManager v1alpha1.VerificationRulesManager
	logger                   *zap.Logger
}

func NewService(verificationRulesManager v1alpha1.VerificationRulesManager, logger *zap.Logger) *Service {
	return &Service{
		verificationRulesManager: verificationRulesManager,
		logger:                   logger,
	}
}

func (s *Service) GetVerificationRule() map[string]map[string]v1alpha1.VerificationRule {
	return s.verificationRulesManager.GetRules()
}

func (s *Service) AddVerificationRule(pushedVerificationRule v1alpha1.VerificationRule) {
	s.verificationRulesManager.AddRule(pushedVerificationRule)
}
