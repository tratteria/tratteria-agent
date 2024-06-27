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
	verificationRules := h.service.GetVerificationRule()

	response, err := json.Marshal(verificationRules)
	if err != nil {
		http.Error(w, "Failed to encode verification rules", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func (h *Handlers) ConfigWebhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read pushed verification rule request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}
	defer r.Body.Close()

	var verificationRule v1alpha1.VerificationRule

	if err := json.Unmarshal(body, &verificationRule); err != nil {
		h.logger.Error("Failed to unmarshal pushed verification rule", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	h.logger.Info("Received pushed verification rule",
		zap.String("endpoint", verificationRule.Endpoint),
		zap.String("method", verificationRule.Method))

	h.service.AddVerificationRule(verificationRule)

	w.WriteHeader(http.StatusOK)
}
