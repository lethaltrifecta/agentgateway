use agentgateway::http;
use anyhow::Context;
use futures_util::StreamExt;
use itertools::Itertools;
use rmcp::model::*;
use rmcp::transport::common::http_header::{
	EVENT_STREAM_MIME_TYPE, HEADER_LAST_EVENT_ID, HEADER_SESSION_ID, JSON_MIME_TYPE,
};
use serde_json::json;
use sse_stream::SseStream;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::gateway::AgentGateway;
use crate::common::mcp::{
	ComprehensiveClient, MockMcpServer, TEST_SESSION_KEY, multiplex_config,
	multiplex_transport_matrix_config, setup_comprehensive_client, simple_multiplex_config,
	start_mock_legacy_sse_server, start_mock_mcp_meta_server, start_mock_mcp_server,
	start_mock_mcp_tools_only_prompt_leak_server,
};

struct MultiplexTestFixture {
	client: ComprehensiveClient,
	update_count: Arc<AtomicUsize>,
	_gw: AgentGateway,
	_mcp1: MockMcpServer,
	_mcp2: MockMcpServer,
	_s3_mock: MockServer,
}

impl MultiplexTestFixture {
	async fn setup() -> anyhow::Result<Self> {
		agent_core::telemetry::testing::setup_test_logging();

		let mcp1 = start_mock_mcp_server("s1", true).await;
		let mcp2 = start_mock_mcp_server("s2", false).await;

		let s3_mock = MockServer::start().await;
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(500).set_body_string("CRASH"))
			.mount(&s3_mock)
			.await;

		let config = multiplex_config(&mcp1, &mcp2, *s3_mock.address());
		let gw = AgentGateway::new(config).await?;
		let mcp_url = format!("http://localhost:{}/mcp", gw.port());
		let update_count = Arc::new(AtomicUsize::new(0));
		let client = setup_comprehensive_client(&mcp_url, update_count.clone()).await?;

		Ok(Self {
			client,
			update_count,
			_gw: gw,
			_mcp1: mcp1,
			_mcp2: mcp2,
			_s3_mock: s3_mock,
		})
	}
}

struct MultiplexTransportMatrixFixture {
	client: ComprehensiveClient,
	update_count: Arc<AtomicUsize>,
	_gw: AgentGateway,
	_streamable: MockMcpServer,
	_sse: MockMcpServer,
	_s3_mock: MockServer,
}

impl MultiplexTransportMatrixFixture {
	async fn setup() -> anyhow::Result<Self> {
		agent_core::telemetry::testing::setup_test_logging();

		let streamable = start_mock_mcp_server("stream", true).await;
		let sse = start_mock_legacy_sse_server().await;

		let s3_mock = MockServer::start().await;
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(500).set_body_string("CRASH"))
			.mount(&s3_mock)
			.await;

		let config = multiplex_transport_matrix_config(&streamable, &sse, *s3_mock.address());
		let gw = AgentGateway::new(config).await?;
		let mcp_url = format!("http://localhost:{}/mcp", gw.port());
		let update_count = Arc::new(AtomicUsize::new(0));
		let client = setup_comprehensive_client(&mcp_url, update_count.clone()).await?;

		Ok(Self {
			client,
			update_count,
			_gw: gw,
			_streamable: streamable,
			_sse: sse,
			_s3_mock: s3_mock,
		})
	}
}

struct EnterpriseMultiplexFixture {
	mcp_url: String,
	labels: Vec<String>,
	stateful_labels: HashSet<String>,
	_gw: AgentGateway,
	_servers: Vec<MockMcpServer>,
	_broken: MockServer,
}

impl EnterpriseMultiplexFixture {
	async fn setup(target_count: usize) -> anyhow::Result<Self> {
		agent_core::telemetry::testing::setup_test_logging();
		assert!(
			target_count >= 20,
			"enterprise tests should use at least 20 targets"
		);

		let mut labels = Vec::with_capacity(target_count);
		let mut stateful_labels = HashSet::with_capacity(target_count / 2 + 1);
		let mut servers = Vec::with_capacity(target_count);
		for i in 0..target_count {
			let label = format!("s{:02}", i + 1);
			let stateful = i % 2 == 0;
			if stateful {
				stateful_labels.insert(label.clone());
			}
			let server = start_mock_mcp_server(label.clone(), stateful).await;
			labels.push(label);
			servers.push(server);
		}

		let broken = MockServer::start().await;
		Mock::given(method("POST"))
			.respond_with(ResponseTemplate::new(500).set_body_string("CRASH"))
			.mount(&broken)
			.await;

		let targets = labels
			.iter()
			.zip(servers.iter())
			.map(|(label, server)| (label.clone(), server.addr))
			.collect_vec();
		let config = enterprise_multiplex_config(&targets, *broken.address());
		let gw = AgentGateway::new(config).await?;
		let mcp_url = format!("http://localhost:{}/mcp", gw.port());

		Ok(Self {
			mcp_url,
			labels,
			stateful_labels,
			_gw: gw,
			_servers: servers,
			_broken: broken,
		})
	}
}

fn enterprise_multiplex_config(
	targets: &[(String, SocketAddr)],
	broken_addr: SocketAddr,
) -> String {
	let mut config = String::from(
		r#"config:
  session:
    key: "#,
	);
	config.push_str(TEST_SESSION_KEY);
	config.push_str(
		r#"
binds:
- port: $PORT
  listeners:
  - name: enterprise-multiplex-gateway
    routes:
    - matches:
      - path:
          pathPrefix: /mcp
      backends:
      - mcp:
          allowDegraded: true
          targets:
"#,
	);

	for (name, addr) in targets {
		config.push_str(&format!(
			"          - name: {name}\n            mcp:\n              host: http://{addr}/mcp\n"
		));
	}

	config.push_str(&format!(
		r#"          - name: dead
            mcp:
              host: http://{}/mcp
      policies:
        mcpAuthorization:
          rules:
          - 'true'
"#,
		broken_addr
	));

	config
}

async fn setup_client_without_updates(gw: &AgentGateway) -> anyhow::Result<ComprehensiveClient> {
	let mcp_url = format!("http://localhost:{}/mcp", gw.port());
	setup_comprehensive_client(&mcp_url, Arc::new(AtomicUsize::new(0))).await
}

fn mcp_post_headers(session_id: Option<&str>) -> http::HeaderMap {
	let mut headers = http::HeaderMap::new();
	headers.insert(
		http::header::ACCEPT,
		http::HeaderValue::from_static("application/json, text/event-stream"),
	);
	if let Some(session_id) = session_id {
		headers.insert(
			HEADER_SESSION_ID,
			http::HeaderValue::from_str(session_id).expect("session id header should be valid"),
		);
	}
	headers
}

fn initialize_request_message(id: i64) -> serde_json::Value {
	serde_json::to_value(ClientJsonRpcMessage::request(
		InitializeRequest::new(ClientInfo::new(
			ClientCapabilities::default(),
			Implementation::new("restart-handoff-test", "1.0.0"),
		))
		.into(),
		RequestId::Number(id),
	))
	.expect("initialize request should serialize")
}

fn initialized_notification_message() -> serde_json::Value {
	serde_json::to_value(ClientJsonRpcMessage::notification(
		ClientNotification::InitializedNotification(InitializedNotification::default()),
	))
	.expect("initialized notification should serialize")
}

fn list_prompts_request_message(id: i64) -> serde_json::Value {
	serde_json::to_value(ClientJsonRpcMessage::request(
		ClientRequest::ListPromptsRequest(ListPromptsRequest {
			method: Default::default(),
			params: Some(PaginatedRequestParams::default()),
			extensions: Default::default(),
		}),
		RequestId::Number(id),
	))
	.expect("list prompts request should serialize")
}

fn list_resources_request_message(id: i64) -> serde_json::Value {
	serde_json::to_value(ClientJsonRpcMessage::request(
		ClientRequest::ListResourcesRequest(ListResourcesRequest {
			method: Default::default(),
			params: Some(PaginatedRequestParams::default()),
			extensions: Default::default(),
		}),
		RequestId::Number(id),
	))
	.expect("list resources request should serialize")
}

fn subscribe_request_message(id: i64, uri: impl Into<String>) -> serde_json::Value {
	json!({
		"jsonrpc": "2.0",
		"id": id,
		"method": "resources/subscribe",
		"params": {
			"uri": uri.into(),
		}
	})
}

fn call_tool_request_message(
	id: i64,
	name: impl Into<std::borrow::Cow<'static, str>>,
	arguments: Option<JsonObject>,
) -> serde_json::Value {
	serde_json::to_value(ClientJsonRpcMessage::request(
		ClientRequest::CallToolRequest(CallToolRequest::new(call_tool_params(
			name, arguments, None,
		))),
		RequestId::Number(id),
	))
	.expect("call tool request should serialize")
}

#[derive(Debug)]
struct StreamEventMessage {
	event_id: String,
	message: ServerJsonRpcMessage,
}

async fn open_event_stream(
	port: u16,
	session_id: &str,
	last_event_id: Option<&str>,
) -> anyhow::Result<reqwest::Response> {
	let client = reqwest::Client::new();
	let mut request = client
		.get(format!("http://localhost:{port}/mcp"))
		.header(reqwest::header::ACCEPT, EVENT_STREAM_MIME_TYPE)
		.header(HEADER_SESSION_ID, session_id);
	if let Some(last_event_id) = last_event_id {
		request = request.header(HEADER_LAST_EVENT_ID, last_event_id);
	}
	let response = request.send().await?.error_for_status()?;
	let content_type = response
		.headers()
		.get(reqwest::header::CONTENT_TYPE)
		.and_then(|value| value.to_str().ok())
		.context("event stream response missing content-type")?;
	anyhow::ensure!(
		content_type.starts_with(EVENT_STREAM_MIME_TYPE),
		"unexpected event stream content-type: {content_type}"
	);
	Ok(response)
}

async fn read_first_sse_message(response: reqwest::Response) -> anyhow::Result<StreamEventMessage> {
	let mut stream = SseStream::from_byte_stream(response.bytes_stream());
	let sse = tokio::time::timeout(Duration::from_secs(5), async {
		loop {
			match stream.next().await {
				Some(Ok(sse)) if sse.data.as_deref().is_some_and(|data| !data.is_empty()) => {
					return Ok(sse);
				},
				Some(Ok(_)) => continue,
				Some(Err(error)) => return Err(anyhow::anyhow!("failed to read SSE event: {error}")),
				None => return Err(anyhow::anyhow!("event stream ended before first message")),
			}
		}
	})
	.await
	.context("timed out waiting for SSE event")??;
	let event_id = sse.id.context("SSE event missing id")?;
	let data = sse.data.context("SSE event missing data")?;
	let message = serde_json::from_str(&data)?;
	Ok(StreamEventMessage { event_id, message })
}

fn resource_updated_uri(message: &ServerJsonRpcMessage) -> anyhow::Result<&str> {
	let ServerJsonRpcMessage::Notification(notification) = message else {
		anyhow::bail!("expected notification message, got {message:?}");
	};
	let ServerNotification::ResourceUpdatedNotification(update) = &notification.notification else {
		anyhow::bail!(
			"expected resources/updated notification, got {:?}",
			notification.notification
		);
	};
	Ok(update.params.uri.as_str())
}

async fn read_server_message(resp: http::Response) -> anyhow::Result<ServerJsonRpcMessage> {
	let status = resp.status();
	let content_type = resp
		.headers()
		.get(http::header::CONTENT_TYPE)
		.and_then(|v| v.to_str().ok())
		.map(ToOwned::to_owned);
	let body = http::read_body_with_limit(resp.into_body(), 64 * 1024).await?;
	anyhow::ensure!(
		status.is_success(),
		"unexpected MCP response status {status}: {}",
		String::from_utf8_lossy(&body)
	);
	match content_type.as_deref() {
		Some(value) if value.starts_with(JSON_MIME_TYPE) => Ok(serde_json::from_slice(&body)?),
		Some(value) if value.starts_with(EVENT_STREAM_MIME_TYPE) => {
			let payload = String::from_utf8(body.to_vec())?;
			let event_data = payload
				.lines()
				.filter_map(|line| line.strip_prefix("data:"))
				.map(str::trim_start)
				.collect::<Vec<_>>()
				.join("\n");
			anyhow::ensure!(
				!event_data.is_empty(),
				"SSE MCP response did not contain a data event: {payload:?}"
			);
			Ok(serde_json::from_str(&event_data)?)
		},
		_ => anyhow::bail!("unexpected MCP response content-type: {:?}", content_type),
	}
}

async fn unused_loopback_addr() -> anyhow::Result<SocketAddr> {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let addr = listener.local_addr()?;
	drop(listener);
	Ok(addr)
}

fn assert_prefixed_by(name: &str, target: &str) {
	assert!(
		name.starts_with(&format!("{target}__")),
		"expected '{name}' to be prefixed by '{target}__'"
	);
}

fn assert_wrapped_uri_for_target(uri: &str, target: &str) {
	assert!(
		uri.starts_with(&format!("agw://{target}/")),
		"expected URI '{uri}' to be wrapped for target '{target}'"
	);
}

fn call_tool_params(
	name: impl Into<std::borrow::Cow<'static, str>>,
	arguments: Option<JsonObject>,
	task: Option<JsonObject>,
) -> CallToolRequestParams {
	let mut params = CallToolRequestParams::new(name);
	if let Some(arguments) = arguments {
		params = params.with_arguments(arguments);
	}
	if let Some(task) = task {
		params = params.with_task(task);
	}
	params
}

fn unsubscribe_request_params(uri: impl Into<String>) -> UnsubscribeRequestParams {
	serde_json::from_value(json!({ "uri": uri.into() })).expect("unsubscribe params should be valid")
}

#[tokio::test]
async fn test_tools_aggregation_and_rbac_filtering() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let tools = client.list_tools(None).await?;
	let names = tools.tools.iter().map(|t| t.name.to_string()).collect_vec();
	let s1_echo = names
		.iter()
		.find(|name| name.as_str() == "s1__echo")
		.expect("s1__echo missing");
	assert_prefixed_by(s1_echo, "s1");
	assert!(
		!names.contains(&"s2__echo".into()),
		"RBAC failed to filter s2__echo"
	);
	assert!(
		!names.iter().any(|n| n.starts_with("s3__")),
		"Broken backend tools leaked into list"
	);

	let tool_resp = client
		.call_tool(call_tool_params(
			"s1__echo",
			Some(json!({"val": "hello"}).as_object().unwrap().clone()),
			None,
		))
		.await?;

	let tool_val = serde_json::to_value(&tool_resp.content[0])?;
	assert_eq!(
		tool_val.get("text").and_then(|v| v.as_str()),
		Some("s1: hello")
	);
	Ok(())
}

#[tokio::test]
async fn test_tools_multiplex_preserves_upstream_meta_labels() -> anyhow::Result<()> {
	agent_core::telemetry::testing::setup_test_logging();
	let left = start_mock_mcp_meta_server("mcp", true).await;
	let right = start_mock_mcp_meta_server("sse", true).await;
	let gw = AgentGateway::new(simple_multiplex_config(
		"meta-gateway",
		&[
			("mcp".to_string(), left.addr),
			("sse".to_string(), right.addr),
		],
	))
	.await?;
	let client = setup_client_without_updates(&gw).await?;

	let tools = client.list_tools(None).await?;
	let meta = tools.meta.expect("merged meta should be present");
	let upstreams = meta
		.0
		.get("upstreams")
		.and_then(|v| v.as_object())
		.expect("meta.upstreams");
	let mcp_label = upstreams
		.get("mcp")
		.and_then(|v| v.get("label"))
		.and_then(|v| v.as_str());
	let sse_label = upstreams
		.get("sse")
		.and_then(|v| v.get("label"))
		.and_then(|v| v.as_str());
	assert_eq!(mcp_label, Some("mcp"));
	assert_eq!(sse_label, Some("sse"));
	Ok(())
}

#[tokio::test]
async fn test_resources_list_partial_success_with_one_failing_upstream() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let resources = client.list_resources(None).await?;
	let names = resources
		.resources
		.iter()
		.map(|r| r.name.to_string())
		.collect_vec();
	assert!(names.contains(&"s1__data".to_string()));
	assert!(names.contains(&"s2__data".to_string()));
	assert!(
		!names.iter().any(|name| name.starts_with("s3__")),
		"partial-success fanout failed; expected failing upstream s3 to be excluded"
	);
	Ok(())
}

#[tokio::test]
async fn test_tasks_lifecycle_multiplex() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let task_call = client
		.send_request(ClientRequest::CallToolRequest(CallToolRequest::new(
			call_tool_params(
				"s1__echo",
				Some(json!({"val": "task-hello"}).as_object().unwrap().clone()),
				Some(JsonObject::default()),
			),
		)))
		.await?;
	let task_id = match task_call {
		ServerResult::CreateTaskResult(result) => result.task.task_id,
		other => panic!("Expected CreateTaskResult for task call, got: {:?}", other),
	};
	assert_prefixed_by(&task_id, "s1");

	let listed_tasks = client
		.send_request(ClientRequest::ListTasksRequest(ListTasksRequest {
			method: Default::default(),
			params: Some(PaginatedRequestParams::default()),
			extensions: Default::default(),
		}))
		.await?;
	let listed_tasks = match listed_tasks {
		ServerResult::ListTasksResult(result) => result,
		other => panic!("Expected ListTasksResult, got: {:?}", other),
	};
	assert!(
		listed_tasks
			.tasks
			.iter()
			.any(|task| task.task_id == task_id),
		"Task not returned in list/tasks response"
	);

	let task_info = client
		.send_request(ClientRequest::GetTaskInfoRequest(GetTaskInfoRequest::new(
			GetTaskInfoParams {
				meta: None,
				task_id: task_id.clone(),
			},
		)))
		.await?;
	let task_info = match task_info {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/info, got: {:?}", other),
	};
	assert_eq!(task_info.task_id, task_id);
	assert_eq!(task_info.status, TaskStatus::Completed);

	let task_payload = client
		.send_request(ClientRequest::GetTaskResultRequest(
			GetTaskResultRequest::new(GetTaskResultParams {
				meta: None,
				task_id: task_id.clone(),
			}),
		))
		.await?;
	let task_payload = match task_payload {
		ServerResult::CustomResult(result) => result.0,
		other => panic!("Expected CustomResult for tasks/result, got: {:?}", other),
	};
	assert_eq!(
		task_payload.get("tool").and_then(|v| v.as_str()),
		Some("echo")
	);
	assert_eq!(
		task_payload
			.get("arguments")
			.and_then(|v| v.get("val"))
			.and_then(|v| v.as_str()),
		Some("task-hello")
	);

	let task_cancel = client
		.send_request(ClientRequest::CancelTaskRequest(CancelTaskRequest::new(
			CancelTaskParams {
				meta: None,
				task_id: task_id.clone(),
			},
		)))
		.await?;
	let task_cancel = match task_cancel {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/cancel, got: {:?}", other),
	};
	assert_eq!(task_cancel.task_id, task_id);
	assert_eq!(task_cancel.status, TaskStatus::Cancelled);
	Ok(())
}

#[tokio::test]
async fn test_prompts_list_errors_when_all_targeted_upstreams_fail() -> anyhow::Result<()> {
	agent_core::telemetry::testing::setup_test_logging();
	let meta = start_mock_mcp_meta_server("meta", true).await;
	let dead_addr = {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		drop(listener);
		addr
	};

	let gw = AgentGateway::new(simple_multiplex_config(
		"prompt-fail-gateway",
		&[
			("meta".to_string(), meta.addr),
			("dead".to_string(), dead_addr),
		],
	))
	.await?;
	let client = setup_client_without_updates(&gw).await?;

	let err = client
		.list_prompts(None)
		.await
		.expect_err("expected all targeted upstreams to fail");
	match err {
		rmcp::ServiceError::McpError(mcp_error) => {
			assert_eq!(mcp_error.code.0, -32600);
			assert!(
				mcp_error
					.message
					.contains("all eligible backends failed for method prompts/list"),
				"unexpected error message: {}",
				mcp_error.message
			);
		},
		other => panic!("Expected ServiceError::McpError, got: {:?}", other),
	}

	Ok(())
}

#[tokio::test]
async fn test_prompts_multiplex_roundtrip() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let prompts = client.list_prompts(None).await?;
	assert!(prompts.prompts.iter().any(|p| p.name == "s1__test_prompt"));

	let prompt_resp = client
		.get_prompt(
			GetPromptRequestParams::new("s1__test_prompt")
				.with_arguments(json!({"val": "world"}).as_object().unwrap().clone()),
		)
		.await?;

	let prompt_val = serde_json::to_value(&prompt_resp.messages[0].content)?;
	assert_eq!(
		prompt_val.get("text").and_then(|v| v.as_str()),
		Some("val: world")
	);
	Ok(())
}

#[tokio::test]
async fn test_multiplex_session_restart_resume() -> anyhow::Result<()> {
	let listener_name = "restart-handoff";
	let s1 = start_mock_mcp_tools_only_prompt_leak_server("s1", true).await;
	let s2 = start_mock_mcp_server("s2", true).await;
	let dead_s3_addr = unused_loopback_addr().await?;
	let gw_a = AgentGateway::new(simple_multiplex_config(
		listener_name,
		&[
			("s1".to_string(), s1.addr),
			("s2".to_string(), s2.addr),
			("s3".to_string(), dead_s3_addr),
		],
	))
	.await?;

	let initialize_response = gw_a
		.send_request_json_with_headers(
			"http://localhost/mcp",
			initialize_request_message(1),
			&mcp_post_headers(None),
		)
		.await;
	let session_id = initialize_response
		.headers()
		.get(HEADER_SESSION_ID)
		.and_then(|v| v.to_str().ok())
		.map(ToOwned::to_owned)
		.expect("initialize should mint an MCP session id");
	let initialize_message = read_server_message(initialize_response).await?;
	let initialize_result = match initialize_message {
		ServerJsonRpcMessage::Response(resp) => match resp.result {
			ServerResult::InitializeResult(result) => result,
			other => panic!("expected initialize result, got: {other:?}"),
		},
		other => panic!("expected initialize response, got: {other:?}"),
	};
	assert!(
		initialize_result.capabilities.tools.is_some(),
		"merged initialize should retain tool capability"
	);
	assert!(
		initialize_result.capabilities.prompts.is_some(),
		"merged initialize should retain prompt capability"
	);

	let initialized_response = gw_a
		.send_request_json_with_headers(
			"http://localhost/mcp",
			initialized_notification_message(),
			&mcp_post_headers(Some(&session_id)),
		)
		.await;
	assert!(
		initialized_response.status().is_success(),
		"initialized notification should be accepted"
	);
	gw_a.shutdown().await;

	let s3_recovered = start_mock_mcp_tools_only_prompt_leak_server("s3", true).await;
	let gw_b = AgentGateway::new(simple_multiplex_config(
		listener_name,
		&[
			("s1".to_string(), s1.addr),
			("s2".to_string(), s2.addr),
			("s3".to_string(), s3_recovered.addr),
		],
	))
	.await?;

	let prompts_response = gw_b
		.send_request_json_with_headers(
			"http://localhost/mcp",
			list_prompts_request_message(2),
			&mcp_post_headers(Some(&session_id)),
		)
		.await;
	let prompts_message = read_server_message(prompts_response).await?;
	let prompts_result = match prompts_message {
		ServerJsonRpcMessage::Response(resp) => match resp.result {
			ServerResult::ListPromptsResult(result) => result,
			other => panic!("expected list prompts result, got: {other:?}"),
		},
		other => panic!("expected list prompts response, got: {other:?}"),
	};
	let prompt_names = prompts_result
		.prompts
		.iter()
		.map(|prompt| prompt.name.to_string())
		.collect_vec();

	assert_eq!(
		prompt_names,
		vec!["s2__test_prompt".to_string()],
		"resume should restore initialize-time capability targeting and exclude recovered non-members"
	);

	Ok(())
}

#[tokio::test]
async fn test_resources_multiplex_uri_wrapping_and_read_roundtrip() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let resources = client.list_resources(None).await?;
	let s1_res = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__data")
		.expect("s1__res missing");
	assert_wrapped_uri_for_target(&s1_res.uri, "s1");

	let s1_template = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__template")
		.expect("s1__template missing");
	assert!(
		s1_template.uri.contains("{id}"),
		"Braces were incorrectly encoded in template: {}",
		s1_template.uri
	);

	// Verify Reading through Wrapped URI
	let r_resp = client
		.read_resource(ReadResourceRequestParams::new(s1_res.uri.clone()))
		.await?;

	let resource_val = serde_json::to_value(&r_resp.contents[0])?;
	assert_eq!(
		resource_val.get("text").and_then(|v| v.as_str()),
		Some("server-data")
	);
	Ok(())
}

#[tokio::test]
async fn test_elicitation_roundtrip_multiplex() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let e_resp = client
		.call_tool(call_tool_params("s1__elicitation", None, None))
		.await?;
	assert_eq!(
		e_resp.structured_content.unwrap().get("color").unwrap(),
		"diamond"
	);
	Ok(())
}

#[tokio::test]
async fn test_url_elicitation_error_passthrough_in_multiplex() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let err = client
		.call_tool(call_tool_params(
			"s1__test_url_elicitation_required",
			None,
			None,
		))
		.await
		.expect_err("Expected URL elicitation error");

	match err {
		rmcp::ServiceError::McpError(mcp_error) => {
			assert_eq!(mcp_error.code, ErrorCode::URL_ELICITATION_REQUIRED);
			assert_eq!(
				mcp_error.message.as_ref(),
				"This request requires more information."
			);
			let data = mcp_error.data.expect("error data should be present");
			let elicitations = data
				.get("elicitations")
				.and_then(|v| v.as_array())
				.expect("elicitations array should be present");
			assert_eq!(elicitations.len(), 1);
			let first = elicitations[0].as_object().expect("elicitation object");
			assert_eq!(first.get("mode").and_then(|v| v.as_str()), Some("url"));
			assert_eq!(
				first.get("elicitationId").and_then(|v| v.as_str()),
				Some("elicit-1")
			);
		},
		other => panic!("Expected ServiceError::McpError, got: {:?}", other),
	}

	Ok(())
}

#[tokio::test]
async fn test_resource_update_notification_after_subscribe() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let resources = client.list_resources(None).await?;
	let s1_res = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__data")
		.expect("s1__res missing");

	client
		.subscribe(SubscribeRequestParams::new(s1_res.uri.clone()))
		.await?;

	client
		.call_tool(call_tool_params("s1__trigger_update", None, None))
		.await?;

	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	while fixture.update_count.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert!(
		fixture.update_count.load(Ordering::SeqCst) > 0,
		"expected at least one resources/updated notification after subscribe"
	);

	Ok(())
}

#[tokio::test]
async fn test_streamable_http_last_event_id_replays_buffered_notification() -> anyhow::Result<()> {
	agent_core::telemetry::testing::setup_test_logging();

	let s1 = start_mock_mcp_server("s1", true).await;
	let s2 = start_mock_mcp_server("s2", false).await;
	let s3_mock = MockServer::start().await;
	Mock::given(method("POST"))
		.respond_with(ResponseTemplate::new(500).set_body_string("CRASH"))
		.mount(&s3_mock)
		.await;

	let gw = AgentGateway::new(multiplex_config(&s1, &s2, *s3_mock.address())).await?;

	let initialize_response = gw
		.send_request_json_with_headers(
			"http://localhost/mcp",
			initialize_request_message(1),
			&mcp_post_headers(None),
		)
		.await;
	let session_id = initialize_response
		.headers()
		.get(HEADER_SESSION_ID)
		.and_then(|v| v.to_str().ok())
		.map(ToOwned::to_owned)
		.expect("initialize should mint an MCP session id");
	let _initialize_message = read_server_message(initialize_response).await?;

	let initialized_response = gw
		.send_request_json_with_headers(
			"http://localhost/mcp",
			initialized_notification_message(),
			&mcp_post_headers(Some(&session_id)),
		)
		.await;
	assert!(
		initialized_response.status().is_success(),
		"initialized notification should be accepted"
	);

	let resources_response = gw
		.send_request_json_with_headers(
			"http://localhost/mcp",
			list_resources_request_message(2),
			&mcp_post_headers(Some(&session_id)),
		)
		.await;
	let resources_message = read_server_message(resources_response).await?;
	let resources_result = match resources_message {
		ServerJsonRpcMessage::Response(resp) => match resp.result {
			ServerResult::ListResourcesResult(result) => result,
			other => panic!("expected list resources result, got: {other:?}"),
		},
		other => panic!("expected list resources response, got: {other:?}"),
	};
	let s1_resource = resources_result
		.resources
		.iter()
		.find(|resource| resource.name == "s1__data")
		.cloned()
		.expect("s1__data resource missing");

	let subscribe_response = gw
		.send_request_json_with_headers(
			"http://localhost/mcp",
			subscribe_request_message(3, s1_resource.uri.clone()),
			&mcp_post_headers(Some(&session_id)),
		)
		.await;
	let _subscribe_message = read_server_message(subscribe_response).await?;

	let first_stream = open_event_stream(gw.port(), &session_id, None).await?;
	let first_event_task = tokio::spawn(async move { read_first_sse_message(first_stream).await });

	let first_update_response = gw
		.send_request_json_with_headers(
			"http://localhost/mcp",
			call_tool_request_message(4, "s1__trigger_update", None),
			&mcp_post_headers(Some(&session_id)),
		)
		.await;
	let _first_update_message = read_server_message(first_update_response).await?;

	let first_event = first_event_task.await??;
	assert_eq!(
		resource_updated_uri(&first_event.message)?,
		s1_resource.uri.as_str(),
		"first event should target the subscribed wrapped URI"
	);

	let second_update_response = gw
		.send_request_json_with_headers(
			"http://localhost/mcp",
			call_tool_request_message(5, "s1__trigger_update", None),
			&mcp_post_headers(Some(&session_id)),
		)
		.await;
	let _second_update_message = read_server_message(second_update_response).await?;
	tokio::time::sleep(Duration::from_millis(100)).await;

	let replay_stream =
		open_event_stream(gw.port(), &session_id, Some(&first_event.event_id)).await?;
	let replayed_event = read_first_sse_message(replay_stream).await?;

	assert_ne!(
		replayed_event.event_id, first_event.event_id,
		"replayed event should advance beyond the cursor"
	);
	assert_eq!(
		resource_updated_uri(&replayed_event.message)?,
		s1_resource.uri.as_str(),
		"replayed event should target the subscribed wrapped URI"
	);

	Ok(())
}

#[tokio::test]
async fn test_multiplex_full_surface_all_supported_operations() -> anyhow::Result<()> {
	let fixture = MultiplexTestFixture::setup().await?;
	let client = &fixture.client;

	let tools = client.list_tools(None).await?;
	let tool_names = tools.tools.iter().map(|t| t.name.to_string()).collect_vec();
	assert!(tool_names.contains(&"s1__echo".to_string()));
	assert!(tool_names.contains(&"s1__elicitation".to_string()));
	assert!(tool_names.contains(&"s1__trigger_update".to_string()));
	assert!(tool_names.contains(&"s2__trigger_update".to_string()));
	assert!(
		!tool_names.contains(&"s2__echo".to_string()),
		"RBAC failed to filter s2__echo"
	);
	assert!(
		!tool_names.iter().any(|name| name.starts_with("s3__")),
		"Broken backend tools leaked into list"
	);

	let tool_resp = client
		.call_tool(call_tool_params(
			"s1__echo",
			Some(json!({"val": "full-flow"}).as_object().unwrap().clone()),
			None,
		))
		.await?;
	let tool_val = serde_json::to_value(&tool_resp.content[0])?;
	assert_eq!(
		tool_val.get("text").and_then(|v| v.as_str()),
		Some("s1: full-flow")
	);

	let prompts = client.list_prompts(None).await?;
	assert!(prompts.prompts.iter().any(|p| p.name == "s1__test_prompt"));
	let prompt_resp = client
		.get_prompt(
			GetPromptRequestParams::new("s1__test_prompt")
				.with_arguments(json!({"val": "world"}).as_object().unwrap().clone()),
		)
		.await?;
	let prompt_val = serde_json::to_value(&prompt_resp.messages[0].content)?;
	assert_eq!(
		prompt_val.get("text").and_then(|v| v.as_str()),
		Some("val: world")
	);

	let resources = client.list_resources(None).await?;
	let resource_names = resources
		.resources
		.iter()
		.map(|r| r.name.to_string())
		.collect_vec();
	assert!(resource_names.contains(&"s1__data".to_string()));
	assert!(resource_names.contains(&"s2__data".to_string()));
	assert!(
		!resource_names.iter().any(|name| name.starts_with("s3__")),
		"partial-success fanout failed; expected failing upstream s3 to be excluded"
	);
	let s1_data = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__data")
		.expect("s1__data missing");
	assert_wrapped_uri_for_target(&s1_data.uri, "s1");
	let s1_resource_template = resources
		.resources
		.iter()
		.find(|r| r.name == "s1__template")
		.expect("s1__template missing");
	assert!(
		s1_resource_template.uri.contains("{id}"),
		"Braces were incorrectly encoded in template: {}",
		s1_resource_template.uri
	);

	let resource_read = client
		.read_resource(ReadResourceRequestParams::new(s1_data.uri.clone()))
		.await?;
	let resource_val = serde_json::to_value(&resource_read.contents[0])?;
	assert_eq!(
		resource_val.get("text").and_then(|v| v.as_str()),
		Some("server-data")
	);

	let templates = client.list_resource_templates(None).await?;
	let template_names = templates
		.resource_templates
		.iter()
		.map(|t| t.name.to_string())
		.collect_vec();
	assert!(template_names.contains(&"s1__template".to_string()));
	assert!(template_names.contains(&"s2__template".to_string()));
	assert!(
		!template_names.iter().any(|name| name.starts_with("s3__")),
		"failing upstream resource templates leaked into list"
	);
	let s1_template = templates
		.resource_templates
		.iter()
		.find(|t| t.name == "s1__template")
		.expect("s1__template resource template missing");
	assert_wrapped_uri_for_target(&s1_template.uri_template, "s1");
	assert!(
		s1_template.uri_template.contains("{id}"),
		"Resource template braces were incorrectly encoded: {}",
		s1_template.uri_template
	);

	let prompt_completion = client
		.complete(CompleteRequestParams::new(
			Reference::for_prompt("s1__test_prompt"),
			ArgumentInfo {
				name: "val".to_string(),
				value: "dial".to_string(),
			},
		))
		.await?;
	assert_eq!(
		prompt_completion.completion.values,
		vec!["s1:prompt:dial".to_string()]
	);

	let resource_completion = client
		.complete(CompleteRequestParams::new(
			Reference::for_resource(s1_data.uri.clone()),
			ArgumentInfo {
				name: "id".to_string(),
				value: "abc".to_string(),
			},
		))
		.await?;
	assert_eq!(
		resource_completion.completion.values,
		vec!["s1:resource:abc".to_string()]
	);

	let task_call = client
		.send_request(ClientRequest::CallToolRequest(CallToolRequest::new(
			call_tool_params(
				"s1__echo",
				Some(json!({"val": "task-hello"}).as_object().unwrap().clone()),
				Some(JsonObject::default()),
			),
		)))
		.await?;
	let task_id = match task_call {
		ServerResult::CreateTaskResult(result) => result.task.task_id,
		other => panic!("Expected CreateTaskResult for task call, got: {:?}", other),
	};
	assert_prefixed_by(&task_id, "s1");
	let listed_tasks = client
		.send_request(ClientRequest::ListTasksRequest(ListTasksRequest {
			method: Default::default(),
			params: Some(PaginatedRequestParams::default()),
			extensions: Default::default(),
		}))
		.await?;
	let listed_tasks = match listed_tasks {
		ServerResult::ListTasksResult(result) => result,
		other => panic!("Expected ListTasksResult, got: {:?}", other),
	};
	assert!(
		listed_tasks
			.tasks
			.iter()
			.any(|task| task.task_id == task_id),
		"Task not returned in list/tasks response"
	);
	let task_info = client
		.send_request(ClientRequest::GetTaskInfoRequest(GetTaskInfoRequest::new(
			GetTaskInfoParams {
				meta: None,
				task_id: task_id.clone(),
			},
		)))
		.await?;
	let task_info = match task_info {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/info, got: {:?}", other),
	};
	assert_eq!(task_info.task_id, task_id);
	assert_eq!(task_info.status, TaskStatus::Completed);
	let task_payload = client
		.send_request(ClientRequest::GetTaskResultRequest(
			GetTaskResultRequest::new(GetTaskResultParams {
				meta: None,
				task_id: task_id.clone(),
			}),
		))
		.await?;
	let task_payload = match task_payload {
		ServerResult::CustomResult(result) => result.0,
		other => panic!("Expected CustomResult for tasks/result, got: {:?}", other),
	};
	assert_eq!(
		task_payload.get("tool").and_then(|v| v.as_str()),
		Some("echo")
	);
	assert_eq!(
		task_payload
			.get("arguments")
			.and_then(|v| v.get("val"))
			.and_then(|v| v.as_str()),
		Some("task-hello")
	);
	let task_cancel = client
		.send_request(ClientRequest::CancelTaskRequest(CancelTaskRequest::new(
			CancelTaskParams {
				meta: None,
				task_id: task_id.clone(),
			},
		)))
		.await?;
	let task_cancel = match task_cancel {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/cancel, got: {:?}", other),
	};
	assert_eq!(task_cancel.task_id, task_id);
	assert_eq!(task_cancel.status, TaskStatus::Cancelled);

	let e_resp = client
		.call_tool(call_tool_params("s1__elicitation", None, None))
		.await?;
	assert_eq!(
		e_resp.structured_content.unwrap().get("color").unwrap(),
		"diamond"
	);

	client
		.subscribe(SubscribeRequestParams::new(s1_data.uri.clone()))
		.await?;
	client
		.call_tool(call_tool_params("s1__trigger_update", None, None))
		.await?;
	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	while fixture.update_count.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert!(
		fixture.update_count.load(Ordering::SeqCst) > 0,
		"expected at least one resources/updated notification after subscribe"
	);
	client
		.unsubscribe(unsubscribe_request_params(s1_data.uri.clone()))
		.await?;

	Ok(())
}

#[tokio::test]
async fn test_multiplex_transport_matrix_end_to_end() -> anyhow::Result<()> {
	let fixture = MultiplexTransportMatrixFixture::setup().await?;
	let client = &fixture.client;

	let tools = client.list_tools(None).await?;
	let tool_names = tools.tools.iter().map(|t| t.name.to_string()).collect_vec();
	assert!(tool_names.contains(&"stream__echo".to_string()));
	assert!(tool_names.contains(&"sse__echo".to_string()));
	assert!(tool_names.contains(&"stream__elicitation".to_string()));
	assert!(
		!tool_names.iter().any(|name| name.starts_with("s3__")),
		"Broken backend tools leaked into list"
	);

	let stream_echo = client
		.call_tool(call_tool_params(
			"stream__echo",
			Some(json!({"val": "hello-stream"}).as_object().unwrap().clone()),
			None,
		))
		.await?;
	let stream_echo_val = serde_json::to_value(&stream_echo.content[0])?;
	assert_eq!(
		stream_echo_val.get("text").and_then(|v| v.as_str()),
		Some("stream: hello-stream")
	);

	let sse_echo = client
		.call_tool(call_tool_params(
			"sse__echo",
			Some(json!({"val": "hello-sse"}).as_object().unwrap().clone()),
			None,
		))
		.await?;
	let sse_echo_val = serde_json::to_value(&sse_echo.content[0])?;
	assert_eq!(
		sse_echo_val.get("text").and_then(|v| v.as_str()),
		Some("sse: hello-sse")
	);

	let stream_elicitation = tokio::time::timeout(
		Duration::from_secs(10),
		client.call_tool(call_tool_params("stream__elicitation", None, None)),
	)
	.await
	.map_err(|_| anyhow::anyhow!("timed out waiting for stream elicitation roundtrip"))??;
	assert_eq!(
		stream_elicitation
			.structured_content
			.unwrap()
			.get("color")
			.unwrap(),
		"diamond"
	);

	let prompts = client.list_prompts(None).await?;
	assert!(
		prompts
			.prompts
			.iter()
			.any(|p| p.name == "stream__test_prompt")
	);
	assert!(prompts.prompts.iter().any(|p| p.name == "sse__test_prompt"));

	let stream_prompt = client
		.get_prompt(
			GetPromptRequestParams::new("stream__test_prompt")
				.with_arguments(json!({"val": "world"}).as_object().unwrap().clone()),
		)
		.await?;
	let stream_prompt_val = serde_json::to_value(&stream_prompt.messages[0].content)?;
	assert_eq!(
		stream_prompt_val.get("text").and_then(|v| v.as_str()),
		Some("val: world")
	);

	let sse_prompt = client
		.get_prompt(
			GetPromptRequestParams::new("sse__test_prompt")
				.with_arguments(json!({"val": "world"}).as_object().unwrap().clone()),
		)
		.await?;
	let sse_prompt_val = serde_json::to_value(&sse_prompt.messages[0].content)?;
	assert_eq!(
		sse_prompt_val.get("text").and_then(|v| v.as_str()),
		Some("sse val: world")
	);

	let resources = client.list_resources(None).await?;
	let stream_res = resources
		.resources
		.iter()
		.find(|r| r.name == "stream__data")
		.expect("stream__data missing");
	let sse_res = resources
		.resources
		.iter()
		.find(|r| r.name == "sse__data")
		.expect("sse__data missing");
	assert_wrapped_uri_for_target(&stream_res.uri, "stream");
	assert_wrapped_uri_for_target(&sse_res.uri, "sse");

	let stream_read = client
		.read_resource(ReadResourceRequestParams::new(stream_res.uri.clone()))
		.await?;
	let stream_read_val = serde_json::to_value(&stream_read.contents[0])?;
	assert_eq!(
		stream_read_val.get("text").and_then(|v| v.as_str()),
		Some("server-data")
	);

	let sse_read = client
		.read_resource(ReadResourceRequestParams::new(sse_res.uri.clone()))
		.await?;
	let sse_read_val = serde_json::to_value(&sse_read.contents[0])?;
	assert_eq!(
		sse_read_val.get("text").and_then(|v| v.as_str()),
		Some("sse-server-data")
	);

	let templates = client.list_resource_templates(None).await?;
	let stream_template = templates
		.resource_templates
		.iter()
		.find(|t| t.name == "stream__template")
		.expect("stream__template missing");
	let sse_template = templates
		.resource_templates
		.iter()
		.find(|t| t.name == "sse__template")
		.expect("sse__template missing");
	assert_wrapped_uri_for_target(&stream_template.uri_template, "stream");
	assert_wrapped_uri_for_target(&sse_template.uri_template, "sse");
	assert!(stream_template.uri_template.contains("{id}"));
	assert!(sse_template.uri_template.contains("{id}"));

	let stream_prompt_completion = client
		.complete(CompleteRequestParams::new(
			Reference::for_prompt("stream__test_prompt"),
			ArgumentInfo {
				name: "val".to_string(),
				value: "dial".to_string(),
			},
		))
		.await?;
	assert_eq!(
		stream_prompt_completion.completion.values,
		vec!["stream:prompt:dial".to_string()]
	);

	let stream_resource_completion = client
		.complete(CompleteRequestParams::new(
			Reference::for_resource(stream_res.uri.clone()),
			ArgumentInfo {
				name: "id".to_string(),
				value: "abc".to_string(),
			},
		))
		.await?;
	assert_eq!(
		stream_resource_completion.completion.values,
		vec!["stream:resource:abc".to_string()]
	);

	let task_call = client
		.send_request(ClientRequest::CallToolRequest(CallToolRequest::new(
			call_tool_params(
				"stream__echo",
				Some(json!({"val": "task-hello"}).as_object().unwrap().clone()),
				Some(JsonObject::default()),
			),
		)))
		.await?;
	let task_id = match task_call {
		ServerResult::CreateTaskResult(result) => result.task.task_id,
		other => panic!("Expected CreateTaskResult for task call, got: {:?}", other),
	};
	assert_prefixed_by(&task_id, "stream");

	let task_info = client
		.send_request(ClientRequest::GetTaskInfoRequest(GetTaskInfoRequest::new(
			GetTaskInfoParams {
				meta: None,
				task_id: task_id.clone(),
			},
		)))
		.await?;
	let task_info = match task_info {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/info, got: {:?}", other),
	};
	assert_eq!(task_info.task_id, task_id);
	assert_eq!(task_info.status, TaskStatus::Completed);

	let task_payload = client
		.send_request(ClientRequest::GetTaskResultRequest(
			GetTaskResultRequest::new(GetTaskResultParams {
				meta: None,
				task_id: task_id.clone(),
			}),
		))
		.await?;
	let task_payload = match task_payload {
		ServerResult::CustomResult(result) => result.0,
		other => panic!("Expected CustomResult for tasks/result, got: {:?}", other),
	};
	assert_eq!(
		task_payload.get("tool").and_then(|v| v.as_str()),
		Some("echo")
	);

	let task_cancel = client
		.send_request(ClientRequest::CancelTaskRequest(CancelTaskRequest::new(
			CancelTaskParams {
				meta: None,
				task_id: task_id.clone(),
			},
		)))
		.await?;
	let task_cancel = match task_cancel {
		ServerResult::GetTaskResult(result) => result.task,
		other => panic!("Expected GetTaskResult for tasks/cancel, got: {:?}", other),
	};
	assert_eq!(task_cancel.task_id, task_id);
	assert_eq!(task_cancel.status, TaskStatus::Cancelled);

	client
		.subscribe(SubscribeRequestParams::new(stream_res.uri.clone()))
		.await?;
	client
		.call_tool(call_tool_params("stream__trigger_update", None, None))
		.await?;
	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	while fixture.update_count.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	assert!(
		fixture.update_count.load(Ordering::SeqCst) > 0,
		"expected at least one resources/updated notification after subscribe"
	);
	client
		.unsubscribe(unsubscribe_request_params(stream_res.uri.clone()))
		.await?;

	Ok(())
}

#[tokio::test]
#[ignore = "enterprise load test; run manually"]
async fn test_enterprise_multiplex_concurrent_load_20_upstreams() -> anyhow::Result<()> {
	const TARGETS: usize = 20;
	const WORKERS: usize = 40;
	const ITERATIONS_PER_WORKER: usize = 14;

	let fixture = EnterpriseMultiplexFixture::setup(TARGETS).await?;
	let labels = Arc::new(fixture.labels.clone());
	let stateful_labels = Arc::new(fixture.stateful_labels.iter().cloned().collect_vec());
	let url = fixture.mcp_url.clone();

	let mut handles = Vec::with_capacity(WORKERS);
	for worker_idx in 0..WORKERS {
		let labels = labels.clone();
		let stateful_labels = stateful_labels.clone();
		let url = url.clone();
		handles.push(tokio::spawn(async move {
			let update_count = Arc::new(AtomicUsize::new(0));
			let client = setup_comprehensive_client(&url, update_count).await?;
			for iter_idx in 0..ITERATIONS_PER_WORKER {
				let target_idx = (worker_idx + iter_idx) % labels.len();
				let mut target = labels[target_idx].clone();
				let input = format!("w{worker_idx}-i{iter_idx}");
				let op_case = (worker_idx + iter_idx) % 7;
				if op_case == 6 {
					let stateful_idx = (worker_idx + iter_idx) % stateful_labels.len();
					target = stateful_labels[stateful_idx].clone();
				}
				let op = async {
					match op_case {
						// tools/call
						0 => {
							let resp = client
								.call_tool(call_tool_params(
									format!("{target}__echo"),
									Some(json!({"val": input}).as_object().unwrap().clone()),
									None,
								))
								.await?;
							let value = serde_json::to_value(&resp.content[0])?;
							assert_eq!(
								value.get("text").and_then(|v| v.as_str()),
								Some(format!("{target}: w{worker_idx}-i{iter_idx}").as_str())
							);
						},
						// prompts/list + prompts/get
						1 => {
							let prompts = client.list_prompts(None).await?;
							assert!(
								prompts
									.prompts
									.iter()
									.any(|p| p.name == format!("{target}__test_prompt")),
								"missing prompt for target {target}"
							);
							let prompt = client
								.get_prompt(
									GetPromptRequestParams::new(format!("{target}__test_prompt"))
										.with_arguments(json!({"val": input}).as_object().unwrap().clone()),
								)
								.await?;
							let value = serde_json::to_value(&prompt.messages[0].content)?;
							assert_eq!(
								value.get("text").and_then(|v| v.as_str()),
								Some(format!("val: {input}").as_str())
							);
						},
						// resources/list + resources/read
						2 => {
							let resources = client.list_resources(None).await?;
							let resource = resources
								.resources
								.iter()
								.find(|r| r.name == format!("{target}__data"))
								.expect("target resource should exist");
							let read = client
								.read_resource(ReadResourceRequestParams::new(resource.uri.clone()))
								.await?;
							let value = serde_json::to_value(&read.contents[0])?;
							assert_eq!(
								value.get("text").and_then(|v| v.as_str()),
								Some("server-data")
							);
						},
						// resources/templates list
						3 => {
							let templates = client.list_resource_templates(None).await?;
							assert!(
								templates
									.resource_templates
									.iter()
									.any(|t| t.name == format!("{target}__template")),
								"missing resource template for target {target}"
							);
						},
						// completion on prompt
						4 => {
							let completion = client
								.complete(CompleteRequestParams::new(
									Reference::for_prompt(format!("{target}__test_prompt")),
									ArgumentInfo {
										name: "val".to_string(),
										value: input.clone(),
									},
								))
								.await?;
							assert_eq!(
								completion.completion.values,
								vec![format!("{target}:prompt:{input}")]
							);
						},
						// completion on resource
						5 => {
							let resources = client.list_resources(None).await?;
							let resource = resources
								.resources
								.iter()
								.find(|r| r.name == format!("{target}__data"))
								.expect("target resource should exist");
							let completion = client
								.complete(CompleteRequestParams::new(
									Reference::for_resource(resource.uri.clone()),
									ArgumentInfo {
										name: "id".to_string(),
										value: input.clone(),
									},
								))
								.await?;
							assert_eq!(
								completion.completion.values,
								vec![format!("{target}:resource:{input}")]
							);
						},
						// task lifecycle
						6 => {
							let task_call = client
								.send_request(ClientRequest::CallToolRequest(CallToolRequest::new(
									call_tool_params(
										format!("{target}__echo"),
										Some(json!({"val": input}).as_object().unwrap().clone()),
										Some(JsonObject::default()),
									),
								)))
								.await?;
							let task_id = match task_call {
								ServerResult::CreateTaskResult(result) => result.task.task_id,
								other => panic!("expected CreateTaskResult, got {other:?}"),
							};
							assert_prefixed_by(&task_id, &target);

							let task_info = client
								.send_request(ClientRequest::GetTaskInfoRequest(GetTaskInfoRequest::new(
									GetTaskInfoParams {
										meta: None,
										task_id: task_id.clone(),
									},
								)))
								.await?;
							let task_info = match task_info {
								ServerResult::GetTaskResult(result) => result.task,
								other => panic!("expected GetTaskResult, got {other:?}"),
							};
							assert_eq!(task_info.task_id, task_id);

							let task_result = client
								.send_request(ClientRequest::GetTaskResultRequest(
									GetTaskResultRequest::new(GetTaskResultParams {
										meta: None,
										task_id: task_id.clone(),
									}),
								))
								.await?;
							let payload = match task_result {
								ServerResult::CustomResult(result) => result.0,
								other => panic!("expected CustomResult, got {other:?}"),
							};
							assert_eq!(payload.get("tool").and_then(|v| v.as_str()), Some("echo"));

							let cancel = client
								.send_request(ClientRequest::CancelTaskRequest(CancelTaskRequest::new(
									CancelTaskParams {
										meta: None,
										task_id: task_id.clone(),
									},
								)))
								.await?;
							let cancelled = match cancel {
								ServerResult::GetTaskResult(result) => result.task,
								other => panic!("expected GetTaskResult from cancel, got {other:?}"),
							};
							assert_eq!(cancelled.task_id, task_id);
							assert_eq!(cancelled.status, TaskStatus::Cancelled);
						},
						_ => unreachable!("op_case is computed as modulo 7"),
					}
					anyhow::Ok(())
				};

				tokio::time::timeout(Duration::from_secs(15), op)
					.await
					.map_err(|_| {
						anyhow::anyhow!("timed out worker={worker_idx} iter={iter_idx} op_case={op_case}")
					})??;
			}
			anyhow::Ok(())
		}));
	}

	for handle in handles {
		handle.await??;
	}

	Ok(())
}

#[tokio::test]
#[ignore = "enterprise interactive load test; run manually"]
async fn test_enterprise_multiplex_interactive_load_20_upstreams() -> anyhow::Result<()> {
	const TARGETS: usize = 20;
	const WORKERS: usize = 12;
	const ITERATIONS_PER_WORKER: usize = 6;

	let fixture = EnterpriseMultiplexFixture::setup(TARGETS).await?;
	let stateful_labels = Arc::new(fixture.stateful_labels.iter().cloned().collect_vec());
	let url = fixture.mcp_url.clone();

	let mut handles = Vec::with_capacity(WORKERS);
	for worker_idx in 0..WORKERS {
		let stateful_labels = stateful_labels.clone();
		let url = url.clone();
		handles.push(tokio::spawn(async move {
			let update_count = Arc::new(AtomicUsize::new(0));
			let client = setup_comprehensive_client(&url, update_count.clone()).await?;
			for iter_idx in 0..ITERATIONS_PER_WORKER {
				let target_idx = (worker_idx + iter_idx) % stateful_labels.len();
				let target = stateful_labels[target_idx].clone();
				let op_case = (worker_idx + iter_idx) % 2;
				let op = async {
					match op_case {
						// elicitation
						0 => {
							let resp = client
								.call_tool(call_tool_params(
									format!("{target}__elicitation"),
									None,
									None,
								))
								.await?;
							assert_eq!(
								resp
									.structured_content
									.as_ref()
									.and_then(|c| c.get("color"))
									.and_then(|v| v.as_str()),
								Some("diamond")
							);
						},
						// subscribe + notify + unsubscribe
						_ => {
							let resources = client.list_resources(None).await?;
							let resource = resources
								.resources
								.iter()
								.find(|r| r.name == format!("{target}__data"))
								.expect("target resource should exist");
							let before_updates = update_count.load(Ordering::SeqCst);
							client
								.subscribe(SubscribeRequestParams::new(resource.uri.clone()))
								.await?;
							client
								.call_tool(call_tool_params(
									format!("{target}__trigger_update"),
									None,
									None,
								))
								.await?;
							let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
							while update_count.load(Ordering::SeqCst) == before_updates
								&& tokio::time::Instant::now() < deadline
							{
								tokio::time::sleep(Duration::from_millis(25)).await;
							}
							assert!(
								update_count.load(Ordering::SeqCst) > before_updates,
								"expected at least one resources/updated notification for {target}"
							);
							client
								.unsubscribe(unsubscribe_request_params(resource.uri.clone()))
								.await?;
						},
					}
					anyhow::Ok(())
				};

				tokio::time::timeout(Duration::from_secs(20), op)
					.await
					.map_err(|_| {
						anyhow::anyhow!(
							"timed out interactive worker={worker_idx} iter={iter_idx} op_case={op_case}"
						)
					})??;
			}
			anyhow::Ok(())
		}));
	}

	for handle in handles {
		handle.await??;
	}

	Ok(())
}
