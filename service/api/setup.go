package api

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tratteria/tratteria-agent/api/handler"
	"github.com/tratteria/tratteria-agent/api/service"
	"github.com/tratteria/tratteria-agent/tratverifier"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

type API struct {
	HttpsApiPort             int
	HttpApiPort              int
	TconfigdUrl              *url.URL
	TconfigdSpiffeId         spiffeid.ID
	VerificationRulesManager v1alpha1.VerificationRulesManager
	TraTVerifier             *tratverifier.TraTVerifier
	X509Source               *workloadapi.X509Source
	Logger                   *zap.Logger
}

func (api *API) Run() error {
	apiService := service.NewService(api.VerificationRulesManager, api.Logger)
	apiHandlers := handler.NewHandlers(apiService, api.Logger)

	errChan := make(chan error, 1)

	go func() {
		err := api.startHTTPServer(apiHandlers)
		if err != nil {
			api.Logger.Error("HTTP server exited with error", zap.Error(err))

			errChan <- err
		}

		close(errChan)
	}()

	if err := api.startHTTPSServer(apiHandlers); err != nil {
		api.Logger.Error("HTTPS server exited with error", zap.Error(err))

		return err
	}

	if err, ok := <-errChan; ok {
		return err
	}

	return nil
}

func (api *API) startHTTPServer(apiHandlers *handler.Handlers) error {
	router := mux.NewRouter()
	router.HandleFunc("/verification-rules", apiHandlers.GetVerificationRulesHandler).Methods("GET")

	srv := &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf("0.0.0.0:%d", api.HttpApiPort),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	api.Logger.Info("Starting HTTP api server...", zap.Int("port", api.HttpApiPort))

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		api.Logger.Error("Failed to start the http api server", zap.Error(err))

		return fmt.Errorf("failed to start the http api server :%w", err)
	}

	return nil
}

func (api *API) startHTTPSServer(apiHandlers *handler.Handlers) error {
	router := mux.NewRouter()
	router.HandleFunc("/verification-trat-rule-webhook", apiHandlers.VerificationTraTRuleWebhookHandler).Methods("POST")
	router.HandleFunc("/verification-tratteria-config-rule-webhook", apiHandlers.VerificationTratteriaConfigRuleWebhookHandler).Methods("POST")

	serverTLSConfig := tlsconfig.MTLSServerConfig(api.X509Source, api.X509Source, tlsconfig.AuthorizeID(api.TconfigdSpiffeId))

	srv := &http.Server{
		Handler:      router,
		Addr:         fmt.Sprintf("0.0.0.0:%d", api.HttpsApiPort),
		TLSConfig:    serverTLSConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	api.Logger.Info("Starting HTTPS api server...", zap.Int("port", api.HttpsApiPort))

	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		api.Logger.Error("Failed to start the https api server", zap.Error(err))

		return fmt.Errorf("failed to start the https api server :%w", err)
	}

	return nil
}
