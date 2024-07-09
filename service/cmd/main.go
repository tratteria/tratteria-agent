package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tratteria/tratteria-agent/api"
	"github.com/tratteria/tratteria-agent/config"
	"github.com/tratteria/tratteria-agent/configsync"
	"github.com/tratteria/tratteria-agent/tratinterceptor"
	"github.com/tratteria/tratteria-agent/tratteriatrustbundlemanager"
	"github.com/tratteria/tratteria-agent/tratverifier"
	"github.com/tratteria/tratteria-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

const X509_SOURCE_TIMEOUT = 15 * time.Second

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

	x509SrcCtx, cancel := context.WithTimeout(context.Background(), X509_SOURCE_TIMEOUT)
	defer cancel()

	x509Source, err := workloadapi.NewX509Source(x509SrcCtx)
	if err != nil {
		logger.Fatal("Failed to create X.509 source", zap.Error(err))
	}

	defer x509Source.Close()

	appConfig := config.GetAppConfig()

	tconfigdMtlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(x509Source, x509Source, tlsconfig.AuthorizeID(appConfig.TconfigdSpiffeId)),
		},
	}

	verificationRules := v1alpha1.NewVerificationRulesImp()
	tratteriaTrustBundleManager := tratteriatrustbundlemanager.NewTratteriaTrustBundleManager(appConfig.TconfigdUrl, tconfigdMtlsClient, appConfig.MyNamespace)
	tratVerifier := tratverifier.NewTraTVerifier(verificationRules, tratteriaTrustBundleManager)

	configSyncClient, err := configsync.NewClient(appConfig.AgentHttpsApiPort, appConfig.TconfigdUrl, appConfig.TconfigdSpiffeId, appConfig.MyNamespace, verificationRules, time.Duration(appConfig.HeartBeatIntervalMinutes)*time.Minute, tconfigdMtlsClient, logger)
	if err != nil {
		logger.Fatal("Error creating configuration sync client for tconfigd", zap.Error(err))
	}

	if err := configSyncClient.Start(); err != nil {
		logger.Fatal("Error establishing communication with tconfigd", zap.Error(err))
	}

	go func() {
		apiServer := &api.API{
			HttpsApiPort:             appConfig.AgentHttpsApiPort,
			HttpApiPort:              appConfig.AgentHttpApiPort,
			TconfigdUrl:              appConfig.TconfigdUrl,
			TconfigdSpiffeId:         appConfig.TconfigdSpiffeId,
			VerificationRulesManager: verificationRules,
			TraTVerifier:             tratVerifier,
			X509Source:               x509Source,
			Logger:                   logger}

		if err := apiServer.Run(); err != nil {
			logger.Fatal("Failed to start API server.", zap.Error(err))
		}
	}()

	go func() {
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

	logger.Info("Shutting down tratteria agent...")
}

func setupSignalHandler(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		cancel()
	}()
}
