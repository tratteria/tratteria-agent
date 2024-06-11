package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/tratteria/tratteria-agent/handler"
	"github.com/tratteria/tratteria-agent/pkg/config"
	"github.com/tratteria/tratteria-agent/pkg/rules"
	"github.com/tratteria/tratteria-agent/pkg/service"
	"github.com/tratteria/tratteria-agent/pkg/trat"
	"github.com/tratteria/tratteria-agent/pkg/tratinterceptor"
	"go.uber.org/zap"
)

type App struct {
	Router                *mux.Router
	Config                *config.Config
	HttpClient            *http.Client
	Rules                 *rules.Rules
	TraTSignatureVerifier *trat.SignatureVerifier
	Logger                *zap.Logger
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Cannot initialize Zap logger: %v.", err)
	}

	defer func() {
		if err := logger.Sync(); err != nil {
			log.Printf("Error syncing logger: %v", err)
		}
	}()

	appConfig := config.GetAppConfig()

	httpClient := &http.Client{}

	rules := rules.NewRules(appConfig.TconfigdUrl, appConfig.ServiceName, httpClient, logger)

	err = rules.Fetch()
	if err != nil {
		logger.Fatal("Error fetching verification rules:", zap.Error(err))
	}

	app := &App{
		Router:     mux.NewRouter(),
		Config:     appConfig,
		HttpClient: httpClient,
		Rules:      rules,
		Logger:     logger,
	}

	// Start listening for intercepted requested for verifying TraTs
	tratInterceptor, err := tratinterceptor.NewTraTInterceptor(app.Config.ServicePort, 9070, app.Logger)
	if err != nil {
		logger.Fatal("Error starting request interceptor for verifying TraTs:", zap.Error(err))
	}

	go tratInterceptor.Start()

	appService := service.NewService(app.Config, app.Rules, app.Logger)
	appHandler := handler.NewHandlers(appService, app.Logger)

	app.initializeRoutes(appHandler)

	srv := &http.Server{
		Handler:      app.Router,
		Addr:         "0.0.0.0:9060",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	logger.Info("Starting agent server on 9060.")

	if err := srv.ListenAndServe(); err != nil {
		app.Logger.Fatal("Failed to start agent server", zap.Error(err))
	}
}

func (a *App) initializeRoutes(handlers *handler.Handlers) {
	a.Router.HandleFunc("/verification-rules", handlers.GetVerificationRulesHandler).Methods("GET")
}
