use axum::response::Response;
use http::StatusCode;
use tracing::warn;
use url::Url;

use super::{CallbackValidation, Error, OAuth2, OAuth2CallContext, ProtocolEndpointKind};
use crate::client::Client;
use crate::http::{PolicyResponse, Request};
use crate::proxy::ProxyError;
use crate::proxy::httpproxy::PolicyClient;

impl OAuth2 {
	#[tracing::instrument(
		skip_all,
		fields(provider_id = %self.config.provider_id, client_id = %self.config.client_id)
	)]
	pub async fn handle_protocol_endpoint(
		&self,
		client: &Client,
		policy_client: &PolicyClient,
		oidc: &crate::http::oauth2::OAuth2TokenService,
		req: &mut Request,
	) -> Result<Response, ProxyError> {
		tracing::debug!(path = req.uri().path(), "handling oauth2 protocol endpoint");
		let runtime = OAuth2CallContext {
			client,
			policy_client,
			oidc,
		};
		let response = match self.protocol_endpoint_kind(req.uri().path())? {
			Some(ProtocolEndpointKind::Logout) => {
				self.handle_logout(req.headers(), self.end_session_endpoint())
			},
			Some(ProtocolEndpointKind::Callback) => {
				let redirect_uri = self.resolve_redirect_uri()?;
				let session_redirect = self.session_redirect_for_callback(req)?;
				if let Some(response) = session_redirect {
					Ok(response)
				} else {
					let (metadata, jwt_validator) = self.resolved_oidc_info()?;
					self
						.handle_callback(
							runtime,
							req.headers(),
							req.uri(),
							CallbackValidation {
								metadata: &metadata,
								jwt_validator: jwt_validator.as_deref(),
							},
							&redirect_uri,
						)
						.await
				}
			},
			None => Err(ProxyError::AuthPolicyConflict(
				"oauth2 protocol endpoint dispatch requires a callback or logout path",
			)),
		}?;
		Self::into_direct_response(response)
	}

	fn session_redirect_for_callback(
		&self,
		req: &Request,
	) -> Result<Option<PolicyResponse>, ProxyError> {
		let redirect_uri = self.resolve_redirect_uri()?;
		if req.uri().path() != redirect_uri.path() {
			return Ok(None);
		}
		let Some(session) = self.get_session(req.headers()) else {
			return Ok(None);
		};
		if session.is_expired() {
			return Ok(None);
		}
		let target = self
			.extract_original_url(req.uri())
			.unwrap_or_else(|| "/".into());
		let target = if Self::is_safe_redirect_target(&target) {
			target
		} else {
			"/".to_string()
		};
		let resp = Response::builder()
			.status(StatusCode::FOUND)
			.header(http::header::LOCATION, target)
			.body(Default::default())
			.map_err(|e| {
				ProxyError::from(Error::Internal(format!(
					"failed to build redirect response: {e}"
				)))
			})?;
		Ok(Some(PolicyResponse::default().with_response(resp)))
	}

	fn protocol_endpoint_kind(&self, path: &str) -> Result<Option<ProtocolEndpointKind>, ProxyError> {
		if self.resolve_redirect_uri()?.path() == path {
			return Ok(Some(ProtocolEndpointKind::Callback));
		}
		if self.config.sign_out_path.as_deref() == Some(path) {
			return Ok(Some(ProtocolEndpointKind::Logout));
		}
		Ok(None)
	}

	pub(crate) fn is_logout_path(&self, path: &str) -> bool {
		self.config.sign_out_path.as_deref() == Some(path)
	}

	fn extract_original_url(&self, uri: &http::Uri) -> Option<String> {
		let state_str = Self::query_param(uri, "state")?;
		let state = self.decrypt_handshake_state(&state_str).ok()?;
		Some(state.original_url)
	}

	pub(super) fn handle_logout(
		&self,
		req_headers: &http::HeaderMap,
		end_session_endpoint: Option<&str>,
	) -> Result<PolicyResponse, ProxyError> {
		let response_headers = self.clear_session_cookies();

		let end_session_redirect = self
			.get_session(req_headers)
			.and_then(|session| self.build_end_session_redirect(&session, end_session_endpoint));

		let mut resp_builder = Response::builder();
		if let Some(location) = end_session_redirect {
			resp_builder = resp_builder
				.status(StatusCode::FOUND)
				.header(http::header::LOCATION, location.as_str());
		} else {
			resp_builder = resp_builder.status(StatusCode::OK);
		}
		let resp = resp_builder.body(Default::default()).map_err(|e| {
			ProxyError::from(Error::Internal(format!(
				"failed to build logout response: {e}"
			)))
		})?;

		Ok(PolicyResponse {
			direct_response: Some(resp),
			response_headers: Some(response_headers),
		})
	}

	fn build_end_session_redirect(
		&self,
		session: &super::state::SessionState,
		end_session_endpoint: Option<&str>,
	) -> Option<Url> {
		let endpoint = end_session_endpoint?;
		let mut redirect =
			match super::ValidatedProviderEndpointUrl::parse(endpoint, "end_session_endpoint") {
				Ok(url) => url.into_url(),
				Err(err) => {
					warn!(endpoint, error = %err, "invalid end_session_endpoint from metadata");
					return None;
				},
			};
		let mut query = redirect
			.query_pairs()
			.into_owned()
			.filter(|(k, _)| k != "client_id" && k != "id_token_hint" && k != "post_logout_redirect_uri")
			.collect::<Vec<_>>();
		query.push(("client_id".to_string(), self.config.client_id.clone()));
		if let Some(id_token) = session.id_token.as_deref() {
			query.push(("id_token_hint".to_string(), id_token.to_string()));
		}
		if let Some(post_logout_redirect_uri) = self.config.post_logout_redirect_uri.as_deref() {
			query.push((
				"post_logout_redirect_uri".to_string(),
				post_logout_redirect_uri.to_string(),
			));
		}
		{
			let mut pairs = redirect.query_pairs_mut();
			pairs.clear();
			for (k, v) in &query {
				pairs.append_pair(k, v);
			}
		}
		Some(redirect)
	}
}
