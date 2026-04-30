package jwks

import (
	"encoding/json"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remoteartifact"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// JwksCache stores fetched JWKS keysets by request key.
type JwksCache struct {
	*remoteartifact.Cache[Keyset]
}

func NewCache() *JwksCache {
	return &JwksCache{Cache: remoteartifact.NewCache(func(keyset Keyset) remotehttp.FetchKey {
		return keyset.RequestKey
	})}
}

func (c *JwksCache) LoadJwksFromStores(stored []Keyset) error {
	return c.Load(stored, validateKeyset)
}

func validateKeyset(keyset Keyset) error {
	jwks := jose.JSONWebKeySet{}
	return json.Unmarshal([]byte(keyset.JwksJSON), &jwks)
}

func (c *JwksCache) GetJwks(requestKey remotehttp.FetchKey) (Keyset, bool) {
	return c.Get(requestKey)
}

func buildKeyset(requestKey remotehttp.FetchKey, requestURL string, jwks jose.JSONWebKeySet) (Keyset, error) {
	serializedJwks, err := json.Marshal(jwks)
	if err != nil {
		return Keyset{}, err
	}
	return Keyset{
		RequestKey: requestKey,
		URL:        requestURL,
		FetchedAt:  time.Now(),
		JwksJSON:   string(serializedJwks),
	}, nil
}

func (c *JwksCache) putKeyset(keyset Keyset) {
	c.Put(keyset)
}

func (c *JwksCache) deleteJwks(requestKey remotehttp.FetchKey) bool {
	return c.Delete(requestKey)
}
