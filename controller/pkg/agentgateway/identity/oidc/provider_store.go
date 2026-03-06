package oidc

import (
	"context"
	"sync"

	"github.com/agentgateway/agentgateway/controller/pkg/apiclient"
	"github.com/agentgateway/agentgateway/controller/pkg/common"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
	"github.com/agentgateway/agentgateway/controller/pkg/pluginsdk/collections"
)

var logger = logging.New("oidc_provider_store")

const RunnableName = "oidc-provider-store"

type Store struct {
	storePrefix     string
	cache           *providerCache
	fetcher         *ProviderFetcher
	configMapSyncer *configMapSyncer
	sourceChanges   <-chan ProviderSource
	cmNameToKey     map[string]string
	l               sync.Mutex
}

func BuildProviderStore(
	ctx context.Context,
	cli apiclient.Client,
	commonCols *collections.CommonCollections,
	sourceChanges <-chan ProviderSource,
	storePrefix string,
	deploymentNamespace string,
) *Store {
	logger.Info("creating oidc provider store")

	cache := NewProviderCache()
	store := &Store{
		storePrefix:     storePrefix,
		cache:           cache,
		sourceChanges:   sourceChanges,
		fetcher:         NewProviderFetcher(cache),
		configMapSyncer: NewConfigMapSyncer(cli, storePrefix, deploymentNamespace, commonCols.KrtOpts),
		cmNameToKey:     make(map[string]string),
	}
	BuildProviderConfigMapNamespacedNameFunc(storePrefix, deploymentNamespace)
	return store
}

func (s *Store) Start(ctx context.Context) error {
	logger.Info("starting oidc provider store")

	storedProviders, err := s.configMapSyncer.LoadProvidersFromConfigMaps(ctx)
	if err != nil {
		logger.Error("error loading oidc provider store from ConfigMaps", "error", err)
	}
	s.cache.LoadProvidersFromStores(storedProviders)

	go s.fetcher.Run(ctx)
	go s.updateSources(ctx)

	<-ctx.Done()
	return nil
}

func (s *Store) SubscribeToUpdates() chan map[string]StoredProvider {
	return s.fetcher.SubscribeToUpdates()
}

func (s *Store) ProviderByConfigMapName(cmName string) (string, StoredProvider, bool) {
	s.l.Lock()
	defer s.l.Unlock()

	key, ok := s.cmNameToKey[cmName]
	if !ok {
		return "", StoredProvider{}, false
	}

	provider, ok := s.cache.GetProvider(key)
	if !ok {
		return "", StoredProvider{}, false
	}
	return key, provider, true
}

func (s *Store) updateSources(ctx context.Context) {
	for {
		select {
		case source := <-s.sourceChanges:
			if source.Deleted {
				logger.Debug(
					"deleting oidc provider source",
					"issuer", source.Issuer,
					"config_map", ProviderConfigMapName(s.storePrefix, source.ResourceKey),
				)
				s.fetcher.RemoveSource(source)

				s.l.Lock()
				delete(s.cmNameToKey, ProviderConfigMapName(s.storePrefix, source.ResourceKey))
				s.l.Unlock()
			} else {
				logger.Debug(
					"updating oidc provider source",
					"issuer", source.Issuer,
					"config_map", ProviderConfigMapName(s.storePrefix, source.ResourceKey),
				)
				if err := s.fetcher.AddOrUpdateSource(source); err != nil {
					logger.Error("error adding/updating oidc provider source", "error", err, "issuer", source.Issuer)
					continue
				}

				s.l.Lock()
				s.cmNameToKey[ProviderConfigMapName(s.storePrefix, source.ResourceKey)] = source.ResourceKey
				s.l.Unlock()
			}
		case <-ctx.Done():
			return
		}
	}
}

func (r *Store) NeedLeaderElection() bool {
	return true
}

func (r *Store) RunnableName() string {
	return RunnableName
}

var _ common.NamedRunnable = &Store{}
var _ interface{ Start(context.Context) error } = &Store{}
var _ interface{ NeedLeaderElection() bool } = &Store{}
var _ interface {
	ProviderByConfigMapName(string) (string, StoredProvider, bool)
} = &Store{}
