package jwks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"istio.io/istio/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remoteartifact"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

const maxRetryDelay = remoteartifact.MaxRetryDelay

type fetchAt = remoteartifact.FetchAt

type fetchState struct {
	source     JwksSource
	generation uint64
}

// Fetcher fetches and periodically refreshes remote JWKS keysets.
// Fetched keysets are stored in JwksCache and updates are sent to subscribers.
type Fetcher struct {
	cache             *JwksCache
	defaultJwksClient JwksHttpClient
	inner             *remoteartifact.Fetcher[Keyset]
}

type JwksHttpClient interface {
	FetchJwks(ctx context.Context, target remotehttp.FetchTarget) (jose.JSONWebKeySet, error)
}

type jwksHttpClientImpl struct {
	Client *http.Client
}

func NewFetcher(cache *JwksCache) *Fetcher {
	// Default client has no TLS or proxy config, so NewFetchClient cannot fail.
	defaultClient, _ := remotehttp.NewFetchClient(nil, "", nil)
	f := &Fetcher{
		cache:             cache,
		defaultJwksClient: &jwksHttpClientImpl{Client: defaultClient},
	}
	f.inner = remoteartifact.NewFetcher("jwks", cache.Cache, f.fetch, func(keyset Keyset) time.Time {
		return keyset.FetchedAt
	})
	return f
}

func (f *Fetcher) Run(ctx context.Context) {
	f.inner.Run(ctx)
}

func (f *Fetcher) maybeFetchJwks(ctx context.Context) {
	f.inner.MaybeFetch(ctx)
}

func (f *Fetcher) SubscribeToUpdates() <-chan sets.Set[remotehttp.FetchKey] {
	return f.inner.SubscribeToUpdates()
}

func (f *Fetcher) AddOrUpdateKeyset(source JwksSource) error {
	return f.inner.AddOrUpdate(source.Request())
}

func (f *Fetcher) RemoveKeyset(requestKey remotehttp.FetchKey) {
	f.inner.Remove(requestKey)
}

// RetireKeyset stops fetching requestKey but keeps its cache entry alive so
// that JWT validation can continue using the old keys until the next
// successful fetch sweeps the orphaned entry.
func (f *Fetcher) RetireKeyset(requestKey remotehttp.FetchKey) {
	f.inner.Retire(requestKey)
}

// SweepOrphans drops any cache entries that do not correspond to a live
// request. Intended to be called once at startup after the request collection
// has synced, to reconcile persisted keysets whose owning policies were
// deleted while the controller was down.
func (f *Fetcher) SweepOrphans() {
	f.inner.SweepOrphans()
}

func (f *Fetcher) lookup(requestKey remotehttp.FetchKey) (fetchState, bool) {
	state, ok := f.inner.Lookup(requestKey)
	if !ok {
		return fetchState{}, false
	}
	return fetchState{
		source:     jwksSourceFromRequest(state.Request),
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

func (f *Fetcher) fetch(ctx context.Context, request remoteartifact.Request) (Keyset, error) {
	source := jwksSourceFromRequest(request)
	requestURL, jwks, err := f.fetchJwks(ctx, source)
	if err != nil {
		return Keyset{}, err
	}
	return buildKeyset(request.RequestKey, requestURL, jwks)
}

func (f *Fetcher) fetchJwks(ctx context.Context, source JwksSource) (string, jose.JSONWebKeySet, error) {
	jwks, err := f.fetchJwksFromTarget(ctx, source.TLSConfig, source.Target, source.ProxyTLSConfig)
	if err != nil {
		return "", jose.JSONWebKeySet{}, err
	}
	return source.Target.URL, jwks, nil
}

func (f *Fetcher) fetchJwksFromTarget(ctx context.Context, tlsConfig *tls.Config, target remotehttp.FetchTarget, proxyTLSConfig *tls.Config) (jose.JSONWebKeySet, error) {
	if tlsConfig != nil || target.ProxyURL != "" {
		client, err := remotehttp.NewFetchClient(tlsConfig, target.ProxyURL, proxyTLSConfig)
		if err != nil {
			return jose.JSONWebKeySet{}, err
		}
		return (&jwksHttpClientImpl{Client: client}).FetchJwks(ctx, target)
	}
	return f.defaultJwksClient.FetchJwks(ctx, target)
}

func (c *jwksHttpClientImpl) FetchJwks(ctx context.Context, target remotehttp.FetchTarget) (jose.JSONWebKeySet, error) {
	log := log.FromContext(ctx)
	log.Info("fetching jwks", "url", target.URL)

	jwks, err := remotehttp.FetchJSON[jose.JSONWebKeySet](ctx, c.Client, target, "jwks")
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("could not fetch JWKS: %w", err)
	}
	return jwks, nil
}

func makeFetchClient(tlsConfig *tls.Config, proxyURL string, proxyTLSConfig *tls.Config) (*http.Client, error) {
	return remotehttp.NewFetchClient(tlsConfig, proxyURL, proxyTLSConfig)
}
