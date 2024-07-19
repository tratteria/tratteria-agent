package tratteriatrustbundlemanager

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tratteria/tratteria-agent/tratteriaagenterrors"
)

const (
	JWKS_ENDPOINT = ".well-known/jwks.json"
)

type TratteriaTrustBundleManager struct {
	keySet             jwk.Set
	tconfigdUrl        *url.URL
	tconfigdMtlsClient *http.Client
	namespace          string
	mu                 sync.RWMutex
}

func NewTratteriaTrustBundleManager(tconfigdUrl *url.URL, tconfigMtlsClient *http.Client, namespace string) *TratteriaTrustBundleManager {
	return &TratteriaTrustBundleManager{
		keySet:             jwk.NewSet(),
		tconfigdUrl:        tconfigdUrl,
		tconfigdMtlsClient: tconfigMtlsClient,
		namespace:          namespace,
	}
}

func (tm *TratteriaTrustBundleManager) GetJWK(ctx context.Context, keyID string) (jwk.Key, error) {
	tm.mu.RLock()
	key, found := tm.keySet.LookupKeyID(keyID)
	tm.mu.RUnlock()

	if found {
		return key, nil
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	if key, found := tm.keySet.LookupKeyID(keyID); found {
		return key, nil
	}

	if err := tm.fetchAndUpdateKeys(ctx); err != nil {
		return nil, err
	}

	if key, found := tm.keySet.LookupKeyID(keyID); found {
		return key, nil
	}

	return nil, tratteriaagenterrors.ErrInvalidKeyID
}

func (tm *TratteriaTrustBundleManager) fetchAndUpdateKeys(ctx context.Context) error {
	jwksURL := *tm.tconfigdUrl
	jwksURL.Path = path.Join(jwksURL.Path, JWKS_ENDPOINT)

	q := jwksURL.Query()

	q.Set("namespace", tm.namespace)

	jwksURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating request for URL %s: %w", jwksURL.String(), err)
	}

	resp, err := tm.tconfigdMtlsClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS from URL %s: %w", jwksURL.String(), err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-ok status code %d from URL %s", resp.StatusCode, jwksURL.String())
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body from URL %s: %w", jwksURL.String(), err)
	}

	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS from URL %s: %w", jwksURL.String(), err)
	}

	tm.keySet = set

	return nil
}
