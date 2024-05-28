package rules

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"go.uber.org/zap"
)

const (
	MaxAttempts  = 5
	InitialDelay = 500 * time.Millisecond
)

type VerificationRule struct {
	Type    string `json:"type"`
	Service string `json:"service"`
	Route   string `json:"route"`
	Method  string `json:"method"`
	Rules   []Rule `json:"rules"`
}

type Rule struct {
	TraTName   string                          `json:"traT-name"`
	AdzMapping map[string]VerificationAdzField `json:"adz-mapping"`
}

type VerificationAdzField struct {
	Path     string `json:"path"`
	Required bool   `json:"required"`
}

type Rules struct {
	trmURL            *url.URL
	service           string
	httpClient        *http.Client
	verificationRules map[string]VerificationRule
	logger            *zap.Logger
}

func NewRules(trmURL *url.URL, service string, httpClient *http.Client, logger *zap.Logger) *Rules {
	return &Rules{
		trmURL:            trmURL,
		service:           service,
		httpClient:        httpClient,
		verificationRules: make(map[string]VerificationRule),
		logger:            logger,
	}
}

func (r *Rules) Fetch() error {
	endpoint := *r.trmURL
	endpoint.Path = path.Join(endpoint.Path, "verification-rules")

	query := endpoint.Query()
	query.Set("service", r.service)
	endpoint.RawQuery = query.Encode()

	delay := InitialDelay

	for i := 0; i < MaxAttempts; i++ {
		resp, err := r.httpClient.Get(endpoint.String())
		if err == nil {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				if err := json.NewDecoder(resp.Body).Decode(&r.verificationRules); err != nil {
					return fmt.Errorf("error decoding verification url: %v", err)
				}
				return nil
			}

			resp.Body.Close()
			r.logger.Error("Received non-OK HTTP status from TRM server %s\n", zap.String("status-code", resp.Status))
		} else {
			r.logger.Error("Error connecting to TRM server: %v\n", zap.Error(err))
		}

		if i < MaxAttempts-1 {
			time.Sleep(delay)
			delay *= 2
		}
	}

	return fmt.Errorf("all attempts failed after %d tries", MaxAttempts)
}

func (r *Rules) GetVerificationRule() map[string]VerificationRule {

	return r.verificationRules
}
