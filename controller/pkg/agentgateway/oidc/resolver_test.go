package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/api/v1alpha1/agentgateway"
	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

func TestResolveOidcEndpointBuildsDirectURL(t *testing.T) {
	target, err := resolveOidcEndpoint(nil, remotehttpResolverFunc(func(input remotehttp.ResolveInput) (*remotehttp.ResolvedTarget, error) {
		t.Fatalf("unexpected backend resolver call: %#v", input)
		return nil, nil
	}), RemoteOidcOwner{
		ID:               OidcOwnerID{Namespace: "default", Name: "policy-a", Path: "spec.traffic.oidc"},
		DefaultNamespace: "default",
		Config: agentgateway.OIDC{
			IssuerURL: "https://issuer.example/tenant-a",
		},
	})

	assert.NoError(t, err)
	assert.Equal(t, "https://issuer.example/tenant-a/.well-known/openid-configuration", target.Target.URL)
}

func TestOidcDiscoveryURL(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		discovery string
	}{
		{
			name:      "host only",
			issuer:    "https://idp.example.com",
			discovery: "https://idp.example.com/.well-known/openid-configuration",
		},
		{
			name:      "trailing slash",
			issuer:    "https://idp.example.com/",
			discovery: "https://idp.example.com/.well-known/openid-configuration",
		},
		{
			name:      "path",
			issuer:    "https://idp.example.com/realms/foo",
			discovery: "https://idp.example.com/realms/foo/.well-known/openid-configuration",
		},
		{
			name:      "path trailing slash",
			issuer:    "https://idp.example.com/realms/foo/",
			discovery: "https://idp.example.com/realms/foo/.well-known/openid-configuration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := oidcDiscoveryURL(tt.issuer)
			assert.NoError(t, err)
			assert.Equal(t, tt.discovery, got)
		})
	}
}

func TestOidcDiscoveryURLRejectsInvalidIssuer(t *testing.T) {
	for _, issuer := range []string{
		"",
		"://bad",
		"ftp://idp.example.com",
		"http://idp.example.com",
		"https://",
		"https://idp.example.com?foo=bar",
		"https://idp.example.com#frag",
	} {
		t.Run(issuer, func(t *testing.T) {
			_, err := oidcDiscoveryURL(issuer)
			assert.Error(t, err)
		})
	}
}

// OIDC Discovery §3 / §4.3 mandate byte-for-byte equality between the
// configured issuer and the discovery document's `issuer` claim. A trailing
// slash must round-trip through ResolveOwner unchanged for IdPs that issue
// trailing-slash issuers.
func TestResolveOwnerPreservesTrailingSlashInExpectedIssuer(t *testing.T) {
	resolver := NewResolver(remotehttpResolverFunc(func(input remotehttp.ResolveInput) (*remotehttp.ResolvedTarget, error) {
		t.Fatalf("unexpected backend resolver call: %#v", input)
		return nil, nil
	}))

	resolved, err := resolver.ResolveOwner(nil, RemoteOidcOwner{
		ID:               OidcOwnerID{Namespace: "default", Name: "policy-a", Path: "spec.traffic.oidc"},
		DefaultNamespace: "default",
		Config:           agentgateway.OIDC{IssuerURL: "https://issuer.example/"},
	})

	assert.NoError(t, err)
	assert.Equal(t, "https://issuer.example/", resolved.ExpectedIssuer)
	assert.Equal(t, "https://issuer.example/.well-known/openid-configuration", resolved.Target.Target.URL)
}

type remotehttpResolverFunc func(input remotehttp.ResolveInput) (*remotehttp.ResolvedTarget, error)

func (f remotehttpResolverFunc) Resolve(_ krt.HandlerContext, input remotehttp.ResolveInput) (*remotehttp.ResolvedTarget, error) {
	return f(input)
}
