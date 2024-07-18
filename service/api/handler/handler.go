package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/tratteria/tratteria-agent/api/service"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

type Handlers struct {
	service *service.Service
	logger  *zap.Logger
}

func NewHandlers(service *service.Service, logger *zap.Logger) *Handlers {
	return &Handlers{
		service: service,
		logger:  logger,
	}
}

func (h *Handlers) GetVerificationRulesHandler(w http.ResponseWriter, r *http.Request) {
	verificationRulesJSON, err := h.service.GetVerificationRulesJSON()
	if err != nil {
		http.Error(w, "Failed to retrieve verification rules JSON", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(verificationRulesJSON)
}

func (h *Handlers) VerificationTraTRuleWebhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read pushed verification trat rule request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	defer r.Body.Close()

	var verificationTraTRule v1alpha1.VerificationTraTRule

	if err := json.Unmarshal(body, &verificationTraTRule); err != nil {
		h.logger.Error("Failed to unmarshal pushed verification trat rule", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	h.logger.Info("Received pushed verification trat rule",
		zap.String("endpoint", verificationTraTRule.Endpoint),
		zap.Any("method", verificationTraTRule.Method))

	err = h.service.AddVerificationEndpointRule(verificationTraTRule)
	if err != nil {
		h.logger.Error("Failed to add pushed verification trat rule", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) VerificationTratteriaConfigRuleWebhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read pushed verification tratteria config rule request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	defer r.Body.Close()

	var verificationTratteriaConfigRule v1alpha1.VerificationTratteriaConfigRule

	if err := json.Unmarshal(body, &verificationTratteriaConfigRule); err != nil {
		h.logger.Error("Failed to unmarshal pushed verification tratteria config rule", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	h.logger.Info("Received pushed verification tratteria config rule")

	h.service.UpdateVerificationTokenRule(verificationTratteriaConfigRule)

	w.WriteHeader(http.StatusOK)
}
