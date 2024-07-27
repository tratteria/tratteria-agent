package service

import (
	"context"
	"encoding/json"

	"github.com/tratteria/tratteria-agent/common"
	"github.com/tratteria/tratteria-agent/tratverifier"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

type Service struct {
	verificationRulesManager v1alpha1.VerificationRulesManager
	traTVerifier             *tratverifier.TraTVerifier
	logger                   *zap.Logger
}

func NewService(verificationRulesManager v1alpha1.VerificationRulesManager, traTVerifier *tratverifier.TraTVerifier, logger *zap.Logger) *Service {
	return &Service{
		verificationRulesManager: verificationRulesManager,
		traTVerifier:             traTVerifier,
		logger:                   logger,
	}
}

func (s *Service) GetVerificationRulesJSON() (json.RawMessage, error) {
	return s.verificationRulesManager.GetRulesJSON()
}

func (s *Service) VerifyTraT(ctx context.Context, rawTrat string, path string, method common.HttpMethod, queryParameters json.RawMessage, headers json.RawMessage, body json.RawMessage) (bool, string, error) {
	return s.traTVerifier.VerifyTraT(ctx, rawTrat, path, method, queryParameters, headers, body)
}
