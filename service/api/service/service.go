package service

import (
	"encoding/json"

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

func (s *Service) GetVerificationRulesJSON() (json.RawMessage, error) {
	return s.verificationRulesManager.GetRulesJSON()
}

func (s *Service) AddVerificationEndpointRule(pushedVerificationEndpointRule v1alpha1.VerificationTraTRule) error {
	return s.verificationRulesManager.AddTraTRule(pushedVerificationEndpointRule)
}

func (s *Service) UpdateVerificationTokenRule(pushedVerificationTokenRule v1alpha1.VerificationTratteriaConfigRule) {
	s.verificationRulesManager.UpdateTratteriaConfigRule(pushedVerificationTokenRule)
}
