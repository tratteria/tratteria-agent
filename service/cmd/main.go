package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tratteria/tratteria-agent/api"
	"github.com/tratteria/tratteria-agent/config"
	"github.com/tratteria/tratteria-agent/configsync"
	"github.com/tratteria/tratteria-agent/tratinterceptor"
	"github.com/tratteria/tratteria-agent/tratteriatrustbundlemanager"
	"github.com/tratteria/tratteria-agent/tratverifier"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
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
	verificationRules := v1alpha1.NewVerificationRules()
	tratteriaTrustBundleManager := tratteriatrustbundlemanager.NewTratteriaTrustBundleManager()
	tratVerifier := tratverifier.NewTraTVerifier(verificationRules, tratteriaTrustBundleManager)
	configSyncClient := configsync.Client{
		WebhookPort:              appConfig.AgentApiPort,
		TconfigdUrl:              appConfig.TconfigdUrl,
		ServiceName:              appConfig.ServiceName,
		VerificationRulesManager: verificationRules,
		HeartbeatInterval:        time.Duration(appConfig.HeartBeatIntervalMinutes) * time.Minute,
		HttpClient:               httpClient,
		Logger:                   logger,
	}

	if err := configSyncClient.Start(); err != nil {
		logger.Fatal("Error establishing communication with tconfigd", zap.Error(err))
	}

	go func() {
		logger.Info("Starting API server...")

		apiServer := &api.API{
			ApiPort:                  appConfig.AgentApiPort,
			TconfigdUrl:              appConfig.TconfigdUrl,
			ServiceName:              appConfig.ServiceName,
			VerificationRulesManager: verificationRules,
			TraTVerifier:             tratVerifier,
			Logger:                   logger}

		if err := apiServer.Run(); err != nil {
			logger.Fatal("Failed to start API server.", zap.Error(err))
		}
	}()

	go func() {
		logger.Info("Starting trat interceptor...")

		tratInterceptor, err := tratinterceptor.NewTraTInterceptor(appConfig.ServicePort, appConfig.AgentInterceptorPort, tratVerifier, logger)
		if err != nil {
			logger.Fatal("Failed to start tratinterceptor.", zap.Error(err))
		}

		err = tratInterceptor.Start()
		if err != nil {
			logger.Fatal("Failed to start tratinterceptor.", zap.Error(err))
		}
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
