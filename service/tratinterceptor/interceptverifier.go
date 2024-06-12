package tratinterceptor

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"go.uber.org/zap"
)

type TraTInterceptor struct {
	ServicePort int
	ProxyPort   int
	Proxy       *httputil.ReverseProxy
	Logger      *zap.Logger
}

func NewTraTInterceptor(servicePort, proxyPort int, logger *zap.Logger) (*TraTInterceptor, error) {
	originalAppURL := "http://localhost:" + strconv.Itoa(servicePort)

	proxy, err := setupProxy(originalAppURL)
	if err != nil {
		return nil, err
	}

	return &TraTInterceptor{
		ServicePort: servicePort,
		ProxyPort:   proxyPort,
		Proxy:       proxy,
		Logger:      logger,
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

func (iv *TraTInterceptor) Start() {
	mux := http.NewServeMux()
	proxyWithMiddleware := iv.tratVerificationMiddleware(iv.Proxy)

	mux.Handle("/", proxyWithMiddleware)

	listenAddress := ":" + strconv.Itoa(iv.ProxyPort)
	server := &http.Server{
		Addr:    listenAddress,
		Handler: mux,
	}

	iv.Logger.Info("Starting intercept verifier server", zap.Int("proxy-port", iv.ProxyPort))

	if err := server.ListenAndServe(); err != nil {
		iv.Logger.Fatal("Failed to start intercept verifier server", zap.String("listenAddress", listenAddress), zap.Error(err))
	}
}

func (iv *TraTInterceptor) tratVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Txn-Token")
		if token == "" || !isValidToken(token) {
			iv.Logger.Warn("Invalid or missing token on request", zap.String("path", r.URL.Path))
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
