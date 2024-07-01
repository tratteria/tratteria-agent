package tratteriatrustbundlemanager

import (
	"context"
	"fmt"
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
	keySet      jwk.Set
	tconfigdUrl *url.URL
	namespace   string
	mu          sync.RWMutex
}

func NewTratteriaTrustBundleManager(tconfigdUrl *url.URL, namespace string) *TratteriaTrustBundleManager {
	return &TratteriaTrustBundleManager{
		keySet:      jwk.NewSet(),
		tconfigdUrl: tconfigdUrl,
		namespace:   namespace,
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

	return nil, fmt.Errorf("jwk not found: %w", tratteriaagenterrors.ErrNotFound)
}

func (tm *TratteriaTrustBundleManager) fetchAndUpdateKeys(ctx context.Context) error {
	jwksURL := *tm.tconfigdUrl
	jwksURL.Path = path.Join(jwksURL.Path, JWKS_ENDPOINT)

	q := jwksURL.Query()
	q.Set("namespace", tm.namespace)
	jwksURL.RawQuery = q.Encode()

	set, err := jwk.Fetch(ctx, jwksURL.String())
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS from tconfigd: %w", err)
	}

	tm.keySet = set

	return nil
}
