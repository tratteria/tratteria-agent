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

	rules := rules.NewRules(appConfig.TrmUrl, appConfig.Service, httpClient, logger)

	err = rules.Fetch()
	if err != nil {
		logger.Fatal("Error fetching verification rules:", zap.Error(err))
	}

	tratSignatureVerifier := trat.NewSignatureVerifier(appConfig.TraTsAudience, appConfig.TraTsIssuer)

	app := &App{
		Router:                mux.NewRouter(),
		Config:                appConfig,
		HttpClient:            httpClient,
		Rules:                 rules,
		TraTSignatureVerifier: tratSignatureVerifier,
		Logger:                logger,
	}

	appService := service.NewService(app.Config, app.Rules, app.TraTSignatureVerifier, app.Logger)
	appHandler := handler.NewHandlers(appService, app.Logger)

	app.initializeRoutes(appHandler)

	srv := &http.Server{
		Handler:      app.Router,
		Addr:         "0.0.0.0:9070",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	logger.Info("Starting server on 9070.")
	log.Fatal(srv.ListenAndServe())
}

func (a *App) initializeRoutes(handlers *handler.Handlers) {
	a.Router.HandleFunc("/verification-rules", handlers.GetVerificationRulesHandler).Methods("GET")
}
