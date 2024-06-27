package tratteriatrustbundlemanager

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/tratteria/tratteria-agent/tratteriaagenterrors"
)

type TratteriaTrustBundleManager struct {
	keySet jwk.Set
	mu     sync.RWMutex
}

func NewTratteriaTrustBundleManager() *TratteriaTrustBundleManager {
	return &TratteriaTrustBundleManager{
		keySet: jwk.NewSet(),
	}
}

func (tm *TratteriaTrustBundleManager) GetJWK(keyID string) (jwk.Key, error) {
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

	if err := tm.fetchAndUpdateKeys(); err != nil {
		return nil, err
	}

	if key, found := tm.keySet.LookupKeyID(keyID); found {
		return key, nil
	}

	return nil, fmt.Errorf("jwk :%w", tratteriaagenterrors.ErrNotFound)
}

func (tm *TratteriaTrustBundleManager) fetchAndUpdateKeys() error {
	// TODO
	return nil
}
