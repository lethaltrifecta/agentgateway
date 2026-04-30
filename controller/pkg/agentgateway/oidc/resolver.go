package oidc

import (
	"fmt"
	"net/url"
	"strings"

	"istio.io/istio/pkg/kube/krt"

	"github.com/agentgateway/agentgateway/controller/pkg/agentgateway/remotehttp"
)

// defaultResolver implements Resolver for direct issuer discovery URLs.
type defaultResolver struct{}

// NewResolver constructs a Resolver for direct OIDC issuer discovery URLs.
func NewResolver() Resolver {
	return defaultResolver{}
}

func (r defaultResolver) ResolveOwner(krtctx krt.HandlerContext, owner RemoteOidcOwner) (*ResolvedOidcRequest, error) {
	endpoint, err := resolveOidcEndpoint(krtctx, owner)
	if err != nil {
		return nil, err
	}

	return &ResolvedOidcRequest{
		OwnerID:        owner.ID,
		ExpectedIssuer: owner.Config.IssuerURL,
		Target:         *endpoint,
		TTL:            owner.TTL,
	}, nil
}

// resolveOidcEndpoint resolves the OIDC discovery URL for the given owner.
func resolveOidcEndpoint(
	_ krt.HandlerContext,
	owner RemoteOidcOwner,
) (*remotehttp.ResolvedTarget, error) {
	issuerURL := owner.Config.IssuerURL
	discoveryURL, err := oidcDiscoveryURL(issuerURL)
	if err != nil {
		return nil, err
	}

	target := remotehttp.FetchTarget{URL: discoveryURL}
	return &remotehttp.ResolvedTarget{
		Key:    target.Key(),
		Target: target,
	}, nil
}

// oidcDiscoveryURL returns <issuerURL>/.well-known/openid-configuration.
func oidcDiscoveryURL(issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL %q: %w", issuerURL, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("issuer URL must be absolute HTTPS without query or fragment")
	}
	base := *u
	discoveryPath, err := oidcDiscoveryPath(issuerURL)
	if err != nil {
		return "", err
	}
	base.Path = "/" + discoveryPath
	return base.String(), nil
}

// oidcDiscoveryPath returns the OIDC discovery path for an issuer URL.
func oidcDiscoveryPath(issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("invalid issuer URL %q: %w", issuerURL, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("issuer URL must be absolute HTTPS without query or fragment")
	}
	return strings.TrimPrefix(strings.TrimRight(u.Path, "/")+"/.well-known/openid-configuration", "/"), nil
}

// requestKeyForDirectIssuer derives the canonical fetch key for an issuer's
// direct (no-backend) discovery URL. Single-sources the `(discovery URL,
// expected issuer)` pair that both the resolver and the persistence layer
// hash, so they cannot drift. The expected issuer is the user-configured
// `issuerURL` verbatim, per OIDC Discovery §3 byte-for-byte matching.
func requestKeyForDirectIssuer(issuerURL string) (remotehttp.FetchKey, error) {
	discoveryURL, err := oidcDiscoveryURL(issuerURL)
	if err != nil {
		return "", err
	}
	target := remotehttp.FetchTarget{URL: discoveryURL}
	return oidcRequestKey(target, issuerURL), nil
}
