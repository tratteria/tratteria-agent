package tratinterceptor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"

	"github.com/tratteria/tratteria-agent/common"
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

	iv.logger.Info("Starting trat interceptor server...", zap.Int("port", iv.proxyPort))

	if err := server.ListenAndServe(); err != nil {
		iv.logger.Error("Failed to start trat intercept.", zap.String("listenAddress", listenAddress), zap.Error(err))

		return fmt.Errorf("failed to start trat interceptor: %w", err)
	}

	return nil
}

func (iv *TraTInterceptor) tratVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trat := r.Header.Get("Txn-Token")

		//TODO: handle keys with multiple values
		queryParams := make(map[string]string)
		for key, values := range r.URL.Query() {
			queryParams[key] = values[0]
		}

		queryParamsJson, err := convertMapToJson(queryParams)
		if err != nil {
			iv.logger.Error("Failed to read request body: error reading query parameters", zap.Error(err))
			http.Error(w, "Error reading request body", http.StatusInternalServerError)

			return
		}

		headersJson, err := convertHeaderToJson(r.Header)
		if err != nil {
			iv.logger.Error("Failed to read request body: error reading request header", zap.Error(err))
			http.Error(w, "Error reading request body", http.StatusInternalServerError)

			return
		}

		body, err := readAndReplaceBody(r)
		if err != nil {
			iv.logger.Error("Failed to read request body", zap.Error(err))
			http.Error(w, "Error reading request body", http.StatusInternalServerError)

			return
		}

		valid, reason, err := iv.traTVerifier.VerifyTraT(r.Context(), trat, r.URL.Path, common.HttpMethod(r.Method), queryParamsJson, headersJson, body)
		if err != nil {
			iv.logger.Error("Error validating trat", zap.Error(err))
			http.Error(w, "Error validating trat", http.StatusInternalServerError)

			return
		}

		if !valid {
			iv.logger.Error("Invalid trat", zap.String("path", r.URL.Path), zap.String("method", r.Method), zap.String("reason", reason))
			http.Error(w, "Invalid trat", http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

func readAndReplaceBody(r *http.Request) (json.RawMessage, error) {
	if r.Body == nil {
		return []byte("{}"), nil
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	r.Body.Close()

	r.Body = io.NopCloser(bytes.NewBuffer(data))

	if len(data) == 0 {
		return []byte("{}"), nil
	}

	return data, nil
}

// TODO: handle keys with multiple values.
func convertHeaderToJson(headers http.Header) (json.RawMessage, error) {
	headerMap := make(map[string]string)
	for key, values := range headers {
		headerMap[key] = values[0]
	}

	return convertMapToJson(headerMap)
}

func convertMapToJson(data map[string]string) (json.RawMessage, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	if len(bytes) == 0 {
		bytes = []byte("{}")
	}

	return json.RawMessage(bytes), nil
}
