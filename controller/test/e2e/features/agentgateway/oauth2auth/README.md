# OAuth2 E2E Suite

This suite validates foundational OAuth2 policy behavior in controller e2e:

- Route- and Gateway-targeted OAuth2 policy attachment.
- OAuth2 provider back-channel routing via `backendRef` (Service).
- API-client challenge behavior (`401` + `WWW-Authenticate`).
- Browser behavior (`302` redirect to authorization endpoint).

The suite uses the shared `testbox` dummy-idp (`dummy-idp.default:8443`) plus
`BackendTLSPolicy` wiring from `testdata/common.yaml` to exercise OIDC discovery
and browser redirect behavior without a separate Keycloak deployment.
