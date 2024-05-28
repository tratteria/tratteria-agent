package service

import (
	"github.com/tratteria/tratteria-agent/pkg/config"
	"github.com/tratteria/tratteria-agent/pkg/rules"
	"github.com/tratteria/tratteria-agent/pkg/trat"
	"go.uber.org/zap"
)

type Service struct {
	config                *config.Config
	rules                 *rules.Rules
	traTSignatureVerifier *trat.SignatureVerifier
	logger                *zap.Logger
}

func NewService(config *config.Config, rules *rules.Rules, traTSignatureVerifier *trat.SignatureVerifier, logger *zap.Logger) *Service {
	return &Service{
		config:                config,
		rules:                 rules,
		traTSignatureVerifier: traTSignatureVerifier,
		logger:                logger,
	}
}

func (s *Service) GetVerificationRule() map[string]rules.VerificationRule {
	return s.rules.GetVerificationRule()
}
