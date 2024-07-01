package api

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/tratteria/tratteria-agent/api/handler"
	"github.com/tratteria/tratteria-agent/api/service"
	"github.com/tratteria/tratteria-agent/tratverifier"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

type API struct {
	ApiPort                  int
	TconfigdUrl              *url.URL
	ServiceName              string
	VerificationRulesManager v1alpha1.VerificationRulesManager
	TraTVerifier             *tratverifier.TraTVerifier
	Logger                   *zap.Logger
}

func NewAPI(tconfigdUrl *url.URL, serviceName string, verificationRulesManager v1alpha1.VerificationRulesManager, logger *zap.Logger) *API {
	return &API{
		TconfigdUrl:              tconfigdUrl,
		ServiceName:              serviceName,
		VerificationRulesManager: verificationRulesManager,
		Logger:                   logger,
	}
}

func (api *API) Run() error {
	apiService := service.NewService(api.VerificationRulesManager, api.Logger)
	apiHandler := handler.NewHandlers(apiService, api.Logger)

	router := mux.NewRouter()
	initializeRoutes(router, apiHandler)

	srv := &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf("0.0.0.0:%d", api.ApiPort),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	api.Logger.Info(fmt.Sprintf("Starting api server on %d...", api.ApiPort))

	if err := srv.ListenAndServe(); err != nil {
		api.Logger.Error("Failed to start api server.", zap.Error(err))

		return fmt.Errorf("failed to start api server: %w", err)
	}

	return nil
}

func initializeRoutes(router *mux.Router, handlers *handler.Handlers) {
	router.HandleFunc("/verification-rules", handlers.GetVerificationRulesHandler).Methods("GET")
	router.HandleFunc("/verification-endpoint-rule-webhook", handlers.VerificationEndpointRuleWebhookHandler).Methods("POST")
	router.HandleFunc("/verification-token-rule-webhook", handlers.VerificationTokenRuleWebhookHandler).Methods("POST")
}
