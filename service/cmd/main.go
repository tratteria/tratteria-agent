package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/tratteria/tratteria-agent/api"
	"github.com/tratteria/tratteria-agent/config"
	"github.com/tratteria/tratteria-agent/rules"
	"github.com/tratteria/tratteria-agent/tratinterceptor"
	"go.uber.org/zap"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandler(cancel)

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
		logger.Fatal("Error fetching verification rules", zap.Error(err))
	}

	go func() {
		logger.Info("Starting API server...")

		apiServer := api.NewAPI(appConfig.TconfigdUrl, appConfig.ServiceName, rules, logger)

		if err := apiServer.Run(); err != nil {
			logger.Fatal("API server failed.", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("Starting trat interceptor...")

		tratInterceptor, err := tratinterceptor.NewTraTInterceptor(appConfig.ServicePort, 9070, logger)
		if err != nil {
			logger.Fatal("Error starting trat interceptor:", zap.Error(err))
		}

		tratInterceptor.Start()
	}()

	<-ctx.Done()

	logger.Info("Shutting down api and interceptor...")
}

func setupSignalHandler(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		cancel()
	}()
}
