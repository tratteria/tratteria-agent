package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/tratteria/tratteria-agent/api/service"
	"github.com/tratteria/tratteria-agent/common"
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

type VerifyTraTRequest struct {
	Path            string            `json:"endpoint"`
	Method          common.HttpMethod `json:"method"`
	QueryParameters json.RawMessage   `json:"queryParameters"`
	Headers         json.RawMessage   `json:"headers"`
	Body            json.RawMessage   `json:"body"`
}

type VerifyTraTResponse struct {
	Valid bool `json:"valid"`
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
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)

		return
	}

	defer r.Body.Close()

	var verificationTraTRule v1alpha1.VerificationTraTRule

	if err := json.Unmarshal(body, &verificationTraTRule); err != nil {
		h.logger.Error("Failed to unmarshal pushed verification trat rule", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)

		return
	}

	h.logger.Info("Received pushed verification trat rule",
		zap.String("endpoint", verificationTraTRule.Endpoint),
		zap.Any("method", verificationTraTRule.Method))

	err = h.service.AddVerificationEndpointRule(verificationTraTRule)
	if err != nil {
		h.logger.Error("Failed to add pushed verification trat rule", zap.Error(err))
		http.Error(w, "Failed to add verification trat rule", http.StatusInternalServerError)

		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) VerificationTratteriaConfigRuleWebhookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read pushed verification tratteria config rule request body", zap.Error(err))
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)

		return
	}

	defer r.Body.Close()

	var verificationTratteriaConfigRule v1alpha1.VerificationTratteriaConfigRule

	if err := json.Unmarshal(body, &verificationTratteriaConfigRule); err != nil {
		h.logger.Error("Failed to unmarshal pushed verification tratteria config rule", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)

		return
	}

	h.logger.Info("Received pushed verification tratteria config rule")

	h.service.UpdateVerificationTokenRule(verificationTratteriaConfigRule)

	w.WriteHeader(http.StatusOK)
}

func (h *Handlers) VerifyTraTHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.logger.Error("Failed to read verify trat request body", zap.Error(err))
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)

		return
	}

	defer r.Body.Close()

	var verifyTraTRequest VerifyTraTRequest

	if err := json.Unmarshal(body, &verifyTraTRequest); err != nil {
		h.logger.Error("Failed to unmarshal verify trat request body", zap.Error(err))
		http.Error(w, "Invalid request", http.StatusBadRequest)

		return
	}

	headers := make(map[string]string)
	if err := json.Unmarshal(verifyTraTRequest.Headers, &headers); err != nil {
		h.logger.Error("Failed to unmarshal headers", zap.Error(err))
		http.Error(w, "Invalid headers format", http.StatusBadRequest)

		return
	}

	trat := headers["Txn-Token"]
	if trat == "" {
		h.logger.Error("Trat missing in request", zap.String("endpoint", verifyTraTRequest.Path), zap.String("method", string(verifyTraTRequest.Method)))
		http.Error(w, "Missing trat", http.StatusUnauthorized)

		return
	}

	h.logger.Info("Received verify trat request", zap.String("endpoint", verifyTraTRequest.Path), zap.String("method", string(verifyTraTRequest.Method)))

	valid, reason, err := h.service.VerifyTraT(r.Context(), trat, verifyTraTRequest.Path, verifyTraTRequest.Method, verifyTraTRequest.QueryParameters, verifyTraTRequest.Headers, verifyTraTRequest.Body)

	if err != nil {
		h.logger.Error("Error validating trat", zap.Error(err))
		http.Error(w, "Error validating trat", http.StatusInternalServerError)

		return
	}

	verifyTraTResponse := VerifyTraTResponse{}

	if !valid {
		verifyTraTResponse.Valid = false

		h.logger.Error("Invalid trat", zap.String("endpoint", verifyTraTRequest.Path), zap.String("method", string(verifyTraTRequest.Method)), zap.String("reason", reason))
	} else {
		verifyTraTResponse.Valid = true
	}

	responseBody, err := json.Marshal(verifyTraTResponse)
	if err != nil {
		h.logger.Error("Failed to marshal response", zap.Error(err))
		http.Error(w, "Failed to process response", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseBody)
}
