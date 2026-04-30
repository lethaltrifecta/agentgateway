package oidc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"istio.io/istio/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remoteartifact"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const maxRetryDelay = remoteartifact.MaxRetryDelay

type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

type fetchAt = remoteartifact.FetchAt

type OidcHttpClient interface {
	FetchDiscovery(ctx context.Context, target remotehttp.FetchTarget) (discoveryDocument, error)
	FetchJwks(ctx context.Context, jwksURI string) (string, error)
}

type oidcHttpClientImpl struct {
	Client *http.Client
}

type fetchState struct {
	source     OidcSource
	generation uint64
}

// Fetcher fetches and periodically refreshes OIDC discovery documents and JWKS.
// Fetched providers are stored in OidcCache and updates are sent to subscribers.
type Fetcher struct {
	cache         *OidcCache
	defaultClient OidcHttpClient
	inner         *remoteartifact.Fetcher[DiscoveredProvider]
}

func NewFetcher(cache *OidcCache) *Fetcher {
	defaultClient, _ := remotehttp.NewFetchClient(nil, "", nil)
	f := &Fetcher{
		cache:         cache,
		defaultClient: &oidcHttpClientImpl{Client: defaultClient},
	}
	f.inner = remoteartifact.NewFetcher("oidc", cache.Cache, f.fetch, func(provider DiscoveredProvider) time.Time {
		return provider.FetchedAt
	})
	return f
}

func (f *Fetcher) Run(ctx context.Context) {
	f.inner.Run(ctx)
}

func (f *Fetcher) maybeFetchOidc(ctx context.Context) {
	f.inner.MaybeFetch(ctx)
}

func (f *Fetcher) SubscribeToUpdates() <-chan sets.Set[remotehttp.FetchKey] {
	return f.inner.SubscribeToUpdates()
}

// AddOrUpdateProvider schedules a fetch for the given OidcSource. When the
// cache already holds a fresh entry, the next fetch is scheduled at
// cached.FetchedAt + source.TTL so a controller restart does not stampede
// the IdP discovery endpoint.
func (f *Fetcher) AddOrUpdateProvider(source OidcSource) error {
	return f.inner.AddOrUpdate(source.Request())
}

// SweepOrphans drops any cache entries that do not correspond to a live
// request. Intended to be called once at startup after the request collection
// has synced, to reconcile persisted providers whose owning policies were
// deleted while the controller was down. Subscribers are notified of the
// evicted keys so the ConfigMap controller can reconcile them away.
func (f *Fetcher) SweepOrphans() {
	f.inner.SweepOrphans()
}

// RemoveOidc removes a tracked provider request and always evicts the cache
// entry, even when no fetcher request was tracked. Persisted cache entries
// seeded by LoadPersistedProviders must be evicted on policy deletion so the
// ConfigMap controller does not re-create the ConfigMap on the next reconcile.
func (f *Fetcher) RemoveOidc(requestKey remotehttp.FetchKey) {
	f.inner.Remove(requestKey)
}

func (f *Fetcher) lookup(requestKey remotehttp.FetchKey) (fetchState, bool) {
	state, ok := f.inner.Lookup(requestKey)
	if !ok {
		return fetchState{}, false
	}
	return fetchState{
		source:     oidcSourceFromRequest(state.Request),
		generation: state.Generation,
	}, true
}

func (f *Fetcher) nextFetchForTest() *fetchAt {
	return f.inner.PeekNextForTest()
}

func (f *Fetcher) scheduledLenForTest() int {
	return f.inner.ScheduledLenForTest()
}

func (f *Fetcher) notifySubscribers(updates sets.Set[remotehttp.FetchKey]) {
	f.inner.NotifyForTest(updates)
}

func nextRetryDelay(retryAttempt int) time.Duration {
	return remoteartifact.NextRetryDelay(retryAttempt)
}

func (f *Fetcher) fetch(ctx context.Context, request remoteartifact.Request) (DiscoveredProvider, error) {
	return f.fetchOidc(ctx, oidcSourceFromRequest(request))
}

func (f *Fetcher) fetchOidc(ctx context.Context, source OidcSource) (DiscoveredProvider, error) {
	client, err := f.clientFor(source.TLSConfig, source.Target, source.ProxyTLSConfig)
	if err != nil {
		return DiscoveredProvider{}, err
	}

	doc, err := client.FetchDiscovery(ctx, source.Target)
	if err != nil {
		return DiscoveredProvider{}, fmt.Errorf("discovery fetch failed: %w", err)
	}
	if err := validateDiscoveryDocument(doc, source.ExpectedIssuer); err != nil {
		return DiscoveredProvider{}, err
	}

	jwksJSON, err := client.FetchJwks(ctx, doc.JwksURI)
	if err != nil {
		return DiscoveredProvider{}, fmt.Errorf("jwks fetch failed: %w", err)
	}

	return DiscoveredProvider{
		RequestKey:                        source.RequestKey,
		IssuerURL:                         doc.Issuer,
		AuthorizationEndpoint:             doc.AuthorizationEndpoint,
		TokenEndpoint:                     doc.TokenEndpoint,
		JwksURI:                           doc.JwksURI,
		JwksJSON:                          jwksJSON,
		TokenEndpointAuthMethodsSupported: doc.TokenEndpointAuthMethodsSupported,
		FetchedAt:                         time.Now(),
	}, nil
}

func validateDiscoveryDocument(doc discoveryDocument, expectedIssuer string) error {
	// RFC 8414 / OIDC Discovery §4.3: reject the document if its issuer does
	// not match what was configured; this prevents token-substitution from a
	// compromised or mis-pointed discovery URL.
	if doc.Issuer != expectedIssuer {
		return fmt.Errorf("issuer mismatch: discovery document reports %q but expected %q", doc.Issuer, expectedIssuer)
	}
	if err := validateAbsoluteHTTPSURL(doc.AuthorizationEndpoint, "authorization_endpoint"); err != nil {
		return err
	}
	if err := validateAbsoluteHTTPSURL(doc.TokenEndpoint, "token_endpoint"); err != nil {
		return err
	}
	if err := validateAbsoluteHTTPSURL(doc.JwksURI, "jwks_uri"); err != nil {
		return err
	}
	return nil
}

func validateAbsoluteHTTPSURL(raw, field string) error {
	if raw == "" {
		return fmt.Errorf("discovery document missing %s", field)
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("discovery document %s must be an absolute HTTPS URL", field)
	}
	return nil
}

func (f *Fetcher) clientFor(tlsConfig *tls.Config, target remotehttp.FetchTarget, proxyTLSConfig *tls.Config) (OidcHttpClient, error) {
	if tlsConfig != nil || target.ProxyURL != "" {
		client, err := remotehttp.NewFetchClient(tlsConfig, target.ProxyURL, proxyTLSConfig)
		if err != nil {
			return nil, err
		}
		return &oidcHttpClientImpl{Client: client}, nil
	}
	return f.defaultClient, nil
}

func (c *oidcHttpClientImpl) FetchDiscovery(ctx context.Context, target remotehttp.FetchTarget) (discoveryDocument, error) {
	log := log.FromContext(ctx)
	log.Info("fetching oidc discovery document", "url", target.URL)

	doc, err := remotehttp.FetchJSON[discoveryDocument](ctx, c.Client, target, "OIDC discovery")
	if err != nil {
		return discoveryDocument{}, err
	}
	return doc, nil
}

func (c *oidcHttpClientImpl) FetchJwks(ctx context.Context, jwksURI string) (string, error) {
	log := log.FromContext(ctx)
	log.Info("fetching jwks from oidc provider", "jwks_uri", jwksURI)

	body, err := remotehttp.FetchBody(ctx, c.Client, jwksURI, "JWKS")
	if err != nil {
		return "", err
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return "", fmt.Errorf("could not decode JWKS: %w", err)
	}

	return string(body), nil
}

func makeFetchClient(tlsConfig *tls.Config, proxyURL string, proxyTLSConfig *tls.Config) (*http.Client, error) {
	return remotehttp.NewFetchClient(tlsConfig, proxyURL, proxyTLSConfig)
}
