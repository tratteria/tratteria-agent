package api

import (
	"fmt"
	"net/http"
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
	VerificationRulesManager v1alpha1.VerificationRulesManager
	TraTVerifier             *tratverifier.TraTVerifier
	Logger                   *zap.Logger
}

func (api *API) Run() error {
	apiService := service.NewService(api.VerificationRulesManager, api.TraTVerifier, api.Logger)
	apiHandlers := handler.NewHandlers(apiService, api.Logger)

	router := mux.NewRouter()
	router.HandleFunc("/verification-rules", apiHandlers.GetVerificationRulesHandler).Methods("GET")
	router.HandleFunc("/verify-trat", apiHandlers.VerifyTraTHandler).Methods("POST")

	srv := &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf("0.0.0.0:%d", api.ApiPort),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	api.Logger.Info("Starting HTTP server...", zap.Int("port", api.ApiPort))

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		api.Logger.Error("Failed to start the http server", zap.Error(err))

		return fmt.Errorf("failed to start the http server :%w", err)
	}

	return nil
}
