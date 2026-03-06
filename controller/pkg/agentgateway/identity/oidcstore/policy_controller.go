package oidcstore

import (
	"context"

	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/identity/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/plugins"
	"github.com/agentgateway/agentgateway/controller/pkg/logging"
)

var polLogger = logging.New("oidc_provider_store_policy_controller")

type OIDCStorePolicyController struct {
	agw           *plugins.AgwCollections
	sources       krt.Collection[oidc.ProviderSource]
	sourceChanges chan oidc.ProviderSource
}

func NewOIDCStorePolicyController(agw *plugins.AgwCollections) *OIDCStorePolicyController {
	polLogger.Info("creating oidc provider store policy controller")
	return &OIDCStorePolicyController{
		agw:           agw,
		sourceChanges: make(chan oidc.ProviderSource),
	}
}

func (c *OIDCStorePolicyController) Init(ctx context.Context) {
	c.sources = krt.NewManyCollection(
		c.agw.AgentgatewayPolicies,
		func(kctx krt.HandlerContext, p *agentgateway.AgentgatewayPolicy) []oidc.ProviderSource {
			pctx := plugins.PolicyCtx{
				Krt:         kctx,
				Collections: c.agw,
			}
			sources := make([]oidc.ProviderSource, 0)
			seen := make(map[string]struct{})

			if p.Spec.Traffic != nil && p.Spec.Traffic.JWTAuthentication != nil {
				for _, provider := range p.Spec.Traffic.JWTAuthentication.Providers {
					if provider.JWKS.OIDC == nil {
						continue
					}
					source, err := plugins.BuildOIDCProviderSource(
						pctx,
						p.Name,
						p.Namespace,
						string(provider.Issuer),
						provider.JWKS.OIDC.BackendRef,
					)
					if err != nil {
						polLogger.Error("error building oidc provider source", "error", err, "policy", p.Name, "issuer", provider.Issuer)
						continue
					}
					if _, ok := seen[source.ResourceKey]; ok {
						continue
					}
					seen[source.ResourceKey] = struct{}{}
					sources = append(sources, *source)
				}
			}

			if p.Spec.Traffic != nil && p.Spec.Traffic.OAuth2 != nil && p.Spec.Traffic.OAuth2.Issuer != nil {
				source, err := plugins.BuildOIDCProviderSource(
					pctx,
					p.Name,
					p.Namespace,
					string(*p.Spec.Traffic.OAuth2.Issuer),
					p.Spec.Traffic.OAuth2.BackendRef,
				)
				if err != nil {
					polLogger.Error("error building oauth2 oidc provider source", "error", err, "policy", p.Name, "issuer", *p.Spec.Traffic.OAuth2.Issuer)
				} else if _, ok := seen[source.ResourceKey]; !ok {
					seen[source.ResourceKey] = struct{}{}
					sources = append(sources, *source)
				}
			}

			return sources
		},
		c.agw.KrtOpts.ToOptions("OIDCProviderSources")...,
	)
}

func (c *OIDCStorePolicyController) Start(ctx context.Context) error {
	polLogger.Info("starting oidc provider store policy controller")
	c.sources.Register(func(event krt.Event[oidc.ProviderSource]) {
		switch event.Event {
		case controllers.EventAdd, controllers.EventUpdate:
			c.sourceChanges <- *event.New
		case controllers.EventDelete:
			deleted := *event.Old
			deleted.Deleted = true
			c.sourceChanges <- deleted
		}
	})

	<-ctx.Done()
	return nil
}

func (c *OIDCStorePolicyController) NeedLeaderElection() bool {
	return true
}

func (c *OIDCStorePolicyController) SourceChanges() chan oidc.ProviderSource {
	return c.sourceChanges
}
