package handler

import (
	"encoding/json"
	"net/http"

	"github.com/tratteria/tratteria-agent/api/service"
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
	h.logger.Info("Received pushed configuration updates")
	// TODO: implement the configuration update
	w.WriteHeader(http.StatusOK)
}
