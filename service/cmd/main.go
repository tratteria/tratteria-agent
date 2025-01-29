package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/tokenetes/tokenetes-agent/api"
	"github.com/tokenetes/tokenetes-agent/config"
	"github.com/tokenetes/tokenetes-agent/configsync"
	"github.com/tokenetes/tokenetes-agent/logging"
	"github.com/tokenetes/tokenetes-agent/tokenetestrustbundlemanager"
	"github.com/tokenetes/tokenetes-agent/tratinterceptor"
	"github.com/tokenetes/tokenetes-agent/tratverifier"
	"github.com/tokenetes/tokenetes-agent/verificationrules/v1alpha1"
	"go.uber.org/zap"
)

const X509_SOURCE_TIMEOUT = 15 * time.Second

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandler(cancel)

	if err := logging.InitLogger(); err != nil {
		panic(err)
	}
	defer logging.Sync()

	mainLogger := logging.GetLogger("main")

	x509SrcCtx, cancel := context.WithTimeout(context.Background(), X509_SOURCE_TIMEOUT)
	defer cancel()

	x509Source, err := workloadapi.NewX509Source(x509SrcCtx)
	if err != nil {
		mainLogger.Fatal("Failed to create X.509 source", zap.Error(err))
	}

	defer x509Source.Close()

	appConfig := config.GetAppConfig()

	verificationRules := v1alpha1.NewVerificationRulesImp()
	configSyncClient := configsync.NewClient(appConfig.TconfigdHost, appConfig.TconfigdSpiffeID, appConfig.MyNamespace, verificationRules, x509Source, logging.GetLogger("config-sync"))

	go func() {
		if err := configSyncClient.Start(ctx); err != nil {
			mainLogger.Fatal("Config sync client stopped with error", zap.Error(err))
		}
	}()

	tokenetesTrustBundleManager := tokenetestrustbundlemanager.NewTokenetesTrustBundleManager(configSyncClient, appConfig.MyNamespace)

	tratVerifier := tratverifier.NewTraTVerifier(verificationRules, tokenetesTrustBundleManager)

	go func() {
		apiServer := &api.API{
			ApiPort:                  appConfig.AgentApiPort,
			VerificationRulesManager: verificationRules,
			TraTVerifier:             tratVerifier,
			Logger:                   logging.GetLogger("api-server")}

		if err := apiServer.Run(); err != nil {
			mainLogger.Fatal("Failed to start HTTP server.", zap.Error(err))
		}
	}()

	if appConfig.InterceptionMode {
		if appConfig.ServicePort == nil {
			mainLogger.Fatal("Failed to start tratinterceptor. Service port not provided.")
		}

		go func() {
			tratInterceptor, err := tratinterceptor.NewTraTInterceptor(*appConfig.ServicePort, appConfig.AgentInterceptorPort, tratVerifier, logging.GetLogger("trat-interceptor"))
			if err != nil {
				mainLogger.Fatal("Failed to start tratinterceptor.", zap.Error(err))
			}

			err = tratInterceptor.Start()
			if err != nil {
				mainLogger.Fatal("Failed to start tratinterceptor.", zap.Error(err))
			}
		}()
	}

	<-ctx.Done()

	mainLogger.Info("Shutting down tokenetes agent...")
}

func setupSignalHandler(cancel context.CancelFunc) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		cancel()
	}()
}
