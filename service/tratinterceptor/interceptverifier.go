package tratinterceptor

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/tratteria/tratteria-agent/tratverifier"
	"go.uber.org/zap"
)

type TraTInterceptor struct {
	servicePort  int
	proxyPort    int
	proxy        *httputil.ReverseProxy
	traTVerifier *tratverifier.TraTVerifier
	logger       *zap.Logger
}

func NewTraTInterceptor(servicePort, proxyPort int, traTVerifier *tratverifier.TraTVerifier, logger *zap.Logger) (*TraTInterceptor, error) {
	originalAppURL := "http://localhost:" + strconv.Itoa(servicePort)

	proxy, err := setupProxy(originalAppURL)
	if err != nil {
		return nil, err
	}

	return &TraTInterceptor{
		servicePort:  servicePort,
		proxyPort:    proxyPort,
		proxy:        proxy,
		traTVerifier: traTVerifier,
		logger:       logger,
	}, nil
}

func setupProxy(target string) (*httputil.ReverseProxy, error) {
	url, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(url)
	proxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Host = url.Host
		req.URL.Scheme = url.Scheme
		req.URL.Host = url.Host
		req.URL.Path = url.Path + req.URL.Path
	}

	return proxy, nil
}

func (iv *TraTInterceptor) Start() error {
	mux := http.NewServeMux()
	proxyWithMiddleware := iv.tratVerificationMiddleware(iv.proxy)

	mux.Handle("/", proxyWithMiddleware)

	listenAddress := ":" + strconv.Itoa(iv.proxyPort)
	server := &http.Server{
		Addr:    listenAddress,
		Handler: mux,
	}

	iv.logger.Info(fmt.Sprintf("Starting trat interceptor server on %d...", iv.proxyPort))

	if err := server.ListenAndServe(); err != nil {
		iv.logger.Error("Failed to start trat intercept.", zap.String("listenAddress", listenAddress), zap.Error(err))

		return fmt.Errorf("failed to start trat interceptor: %w", err)
	}

	return nil
}

func (iv *TraTInterceptor) tratVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Txn-Token")
		if token == "" || !isValidToken(token) {
			iv.logger.Error("Invalid or missing token on request", zap.String("endpoint", r.URL.Path))
			http.Error(w, "Invalid token", http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func isValidToken(token string) bool {
	// TODO: implement TraT verification
	return true
}
