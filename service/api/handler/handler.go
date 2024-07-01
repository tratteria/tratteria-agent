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
		http.Error(w, "Failed to retrive verification rules JSON", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(verificationRulesJSON)
}

func (h *Handlers) VerificationEndpointRuleWebhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read pushed verification endpoint rule request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	defer r.Body.Close()

	var verificationEndpointRule v1alpha1.VerificationEndpointRule

	if err := json.Unmarshal(body, &verificationEndpointRule); err != nil {
		h.logger.Error("Failed to unmarshal pushed verification endpoint rule", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	h.logger.Info("Received pushed verification endpoint rule",
		zap.String("endpoint", verificationEndpointRule.Endpoint),
		zap.Any("method", verificationEndpointRule.Method))

	err = h.service.AddVerificationEndpointRule(verificationEndpointRule)
	if err != nil {
		h.logger.Error("Failed to add pushed verification endpoint rule", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) VerificationTokenRuleWebhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read pushed verification token rule request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	defer r.Body.Close()

	var verificationTokenRule v1alpha1.VerificationTokenRule

	if err := json.Unmarshal(body, &verificationTokenRule); err != nil {
		h.logger.Error("Failed to unmarshal pushed verification token rule", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)

		return
	}

	h.logger.Info("Received pushed verification token rule")

	h.service.UpdateVerificationTokenRule(verificationTokenRule)

	w.WriteHeader(http.StatusOK)
}
