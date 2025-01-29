package tokenetestrustbundlemanager

import (
	"context"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tokenetes/tokenetes-agent/configsync"
	"github.com/tokenetes/tokenetes-agent/tokenetesagenterrors"
)

const (
	JWKS_ENDPOINT = ".well-known/jwks.json"
)

type TokenetesTrustBundleManager struct {
	keySet           jwk.Set
	configSyncClient *configsync.Client
	namespace        string
	mu               sync.RWMutex
}

func NewTokenetesTrustBundleManager(configSyncClient *configsync.Client, namespace string) *TokenetesTrustBundleManager {
	return &TokenetesTrustBundleManager{
		keySet:           jwk.NewSet(),
		configSyncClient: configSyncClient,
		namespace:        namespace,
	}
}

func (tm *TokenetesTrustBundleManager) GetJWK(ctx context.Context, keyID string) (jwk.Key, error) {
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

	return nil, tokenetesagenterrors.ErrInvalidKeyID
}

func (tm *TokenetesTrustBundleManager) fetchAndUpdateKeys(ctx context.Context) error {
	set, err := tm.configSyncClient.GetJWKs(ctx)
	if err != nil {
		return fmt.Errorf("failed to get JWKS: %w", err)
	}

	tm.keySet = set

	return nil
}
