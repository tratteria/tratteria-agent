package service

import (
	"github.com/tratteria/tratteria-agent/pkg/config"
	"github.com/tratteria/tratteria-agent/pkg/rules"
	"go.uber.org/zap"
)

type Service struct {
	config *config.Config
	rules  *rules.Rules
	logger *zap.Logger
}

func NewService(config *config.Config, rules *rules.Rules, logger *zap.Logger) *Service {
	return &Service{
		config: config,
		rules:  rules,
		logger: logger,
	}
}

func (s *Service) GetVerificationRule() map[string]rules.VerificationRule {
	return s.rules.GetVerificationRule()
}
