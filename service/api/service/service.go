package service

import (
	"github.com/tratteria/tratteria-agent/rules"
	"go.uber.org/zap"
)

type Service struct {
	rules  *rules.Rules
	logger *zap.Logger
}

func NewService(rules *rules.Rules, logger *zap.Logger) *Service {
	return &Service{
		rules:  rules,
		logger: logger,
	}
}

func (s *Service) GetVerificationRule() map[string]rules.VerificationRule {
	return s.rules.GetVerificationRule()
}
