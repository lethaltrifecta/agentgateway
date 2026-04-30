package oidc

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v4"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remoteartifact"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// OidcCache stores discovered OIDC providers by request key.
type OidcCache struct {
	*remoteartifact.Cache[DiscoveredProvider]
}

func NewCache() *OidcCache {
	return &OidcCache{Cache: remoteartifact.NewCache(func(provider DiscoveredProvider) remotehttp.FetchKey {
		return provider.RequestKey
	})}
}

func (c *OidcCache) LoadProvidersFromStores(stored []DiscoveredProvider) error {
	return c.Load(stored, validateProvider)
}

func validateProvider(provider DiscoveredProvider) error {
	var jwks jose.JSONWebKeySet
	return json.Unmarshal([]byte(provider.JwksJSON), &jwks)
}

func (c *OidcCache) GetProvider(requestKey remotehttp.FetchKey) (DiscoveredProvider, bool) {
	return c.Get(requestKey)
}

func (c *OidcCache) putProvider(provider DiscoveredProvider) {
	c.Put(provider)
}

func (c *OidcCache) deleteProvider(requestKey remotehttp.FetchKey) bool {
	return c.Delete(requestKey)
}
