package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/shared"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/oidc"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/testutils"
)

func TestResolveOwnerUsesDirectIssuerURL(t *testing.T) {
	policy := gatewayOIDCPolicy()
	ctx := testutils.BuildMockPolicyContext(t, []any{policy})
	owner, ok := oidc.PolicyOIDCLookupOwner(policy.Namespace, policy.Name, policy.Spec.Traffic.OIDC)
	require.True(t, ok)

	resolved, err := oidc.NewResolver(ctx.Resolver).ResolveOwner(ctx.Krt, owner)
	require.NoError(t, err)
	require.NotNil(t, resolved)
	require.Equal(t, "https://issuer.example/.well-known/openid-configuration", resolved.Target.Target.URL)
	require.Equal(t, resolved.Target.Target.Key(), resolved.Target.Key)
	require.Nil(t, resolved.Target.TLSConfig)
	require.Nil(t, resolved.Target.ProxyTLSConfig)
}

func TestResolveOwnerErrorsWhenResolverIsNotInitialized(t *testing.T) {
	policy := gatewayOIDCPolicy()
	ctx := testutils.BuildMockPolicyContext(t, []any{policy})
	owner, ok := oidc.PolicyOIDCLookupOwner(policy.Namespace, policy.Name, policy.Spec.Traffic.OIDC)
	require.True(t, ok)

	resolved, err := oidc.NewResolver(nil).ResolveOwner(ctx.Krt, owner)
	require.EqualError(t, err, "remote http resolver hasn't been initialized")
	require.Nil(t, resolved)
}

func gatewayOIDCPolicy() *agentgateway.AgentgatewayPolicy {
	return &agentgateway.AgentgatewayPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-policy", Namespace: "default"},
		Spec: agentgateway.AgentgatewayPolicySpec{
			TargetRefs: []shared.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: shared.LocalPolicyTargetReference{
					Group: gwv1.Group(gwv1.GroupVersion.Group),
					Kind:  gwv1.Kind("Gateway"),
					Name:  gwv1.ObjectName("super-gateway"),
				},
			}},
			Traffic: &agentgateway.Traffic{
				OIDC: &agentgateway.OIDC{
					IssuerURL:   "https://issuer.example",
					ClientID:    "test-client",
					RedirectURI: "https://app.example/callback",
				},
			},
		},
	}
}
