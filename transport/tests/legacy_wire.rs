//! Wire expectations captured with rmcp 1.3.0, independently of SDK models.
#![allow(clippy::expect_used)]

use std::time::Duration;

use rmcp::ServiceExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use transport::{GatewayConfig, McpShim, ShimConfig};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const DEADLINE: Duration = Duration::from_secs(10);

fn config(url: &str) -> ShimConfig {
    ShimConfig {
        gateways: vec![GatewayConfig {
            name: "fixture".into(),
            url: url.into(),
            token: "synthetic-token".into(),
        }],
        channel_startup_spike: false,
        enable_channels: false,
        read_only: false,
        server_name: "fixture-shim".into(),
        server_version: "0.0.0".into(),
    }
}

struct Wire {
    io: BufReader<DuplexStream>,
    task: tokio::task::JoinHandle<bool>,
}

impl Drop for Wire {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Wire {
    fn new(config: ShimConfig) -> Self {
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            match McpShim::new(config).serve(server).await {
                Ok(service) => service.waiting().await.is_ok(),
                Err(_) => false,
            }
        });
        Self {
            io: BufReader::new(client),
            task,
        }
    }

    async fn send(&mut self, value: Value) {
        let bytes = format!("{value}\n");
        tokio::time::timeout(DEADLINE, self.io.get_mut().write_all(bytes.as_bytes()))
            .await
            .expect("write timeout")
            .expect("write frame");
    }

    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        tokio::time::timeout(DEADLINE, self.io.read_line(&mut line))
            .await
            .expect("read timeout")
            .expect("read frame");
        serde_json::from_str(&line).expect("stdout must contain a JSON frame")
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.send(json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}))
            .await;
        loop {
            let frame = self.receive().await;
            if frame.get("id").is_some() {
                assert_eq!(frame["id"], 2);
                assert_eq!(frame["jsonrpc"], "2.0");
                return frame;
            }
        }
    }

    async fn initialize(&mut self, version: &str) -> Value {
        let result = self.request("initialize", json!({"protocolVersion":version,"capabilities":{},"clientInfo":{"name":"raw-fixture","version":"0"}})).await;
        self.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        result
    }

    async fn finish(&mut self, initialized: bool) {
        self.io.get_mut().shutdown().await.expect("stdin EOF");
        let clean = tokio::time::timeout(DEADLINE, &mut self.task)
            .await
            .expect("server did not terminate on EOF")
            .expect("server task");
        assert_eq!(clean, initialized);
    }
}

fn assert_error(frame: &Value, code: i64) {
    assert_eq!(frame["error"]["code"], code, "{frame}");
    assert!(
        frame.get("result").is_none(),
        "must be a protocol error: {frame}"
    );
    assert!(!frame.to_string().contains("synthetic-token"));
}

#[tokio::test]
async fn baseline_initialization_and_catalog() {
    for requested in ["2024-11-05", "2025-03-26", "2025-06-18", "2099-01-01"] {
        let mut wire = Wire::new(config("http://fixture.invalid"));
        let init = wire.initialize(requested).await;
        let expected = if requested == "2099-01-01" {
            "2025-06-18"
        } else {
            requested
        };
        assert_eq!(init["result"]["protocolVersion"], expected);
        assert_eq!(
            init["result"]["serverInfo"],
            json!({"name":"fixture-shim","version":"0.0.0"})
        );
        assert_eq!(init["result"]["capabilities"], json!({"tools":{}}));
        assert!(
            init["result"]["instructions"]
                .as_str()
                .expect("instructions")
                .contains("forge_info")
        );
        let mut catalog = wire.request("tools/list", json!({})).await;
        catalog["result"]["tools"]
            .as_array_mut()
            .expect("tools")
            .sort_by_key(|tool| tool["name"].as_str().expect("tool name").to_owned());
        // This fixture is recorded before the dependency upgrade. Never update it
        // from the upgraded serializer to make a compatibility failure pass.
        let mut expected: Value = serde_json::from_str(include_str!("fixtures/tools-1.3.json"))
            .expect("baseline catalog");
        // Issue #255 intentionally extends this one tool; keep the recorded
        // SDK baseline intact for every other tool. Its new contract is tested
        // separately below through tools/list and tools/call.
        for frame in [&mut catalog, &mut expected] {
            frame["result"]["tools"]
                .as_array_mut()
                .expect("tools")
                .retain(|tool| tool["name"] != "list_change_requests");
        }
        assert_eq!(catalog, expected);
        for arguments in [None, Some(json!({}))] {
            let mut params = json!({"name":"poll_events"});
            if let Some(arguments) = arguments {
                params["arguments"] = arguments;
            }
            assert_eq!(
                wire.request("tools/call", params).await,
                json!({"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"[]"}],"isError":false}})
            );
        }
        wire.finish(true).await;
    }
}

#[tokio::test]
async fn baseline_argument_and_handler_errors() {
    let server = MockServer::start().await;
    let mut settings = config(&server.uri());
    settings.read_only = true;
    let mut wire = Wire::new(settings);
    wire.initialize("2025-06-18").await;
    for params in [
        json!({"name":"unknown"}),
        json!({"name":"get_issue"}),
        json!({"name":"get_issue","arguments":{}}),
        json!({"name":"get_issue","arguments":{"forge":"fixture","owner":"o","repo":"r","index":false}}),
        json!({"name":"get_issue","arguments":{"forge":"fixture","owner":"o","repo":"r","index":null}}),
        json!({"name":"rebase_branch","arguments":{"forge":"fixture","owner":"o","repo":"r","branch":"agent/test","base_branch":"main","operations":[{"type":"invalid"}]}}),
        json!({"name":"close_issue","arguments":{"forge":"fixture","owner":"o","repo":"r","index":1,"message":"close"}}),
    ] {
        assert_error(&wire.request("tools/call", params).await, -32602);
    }
    wire.finish(true).await;
}

#[tokio::test]
async fn baseline_http_envelopes_and_numeric_strings() {
    for (status, code) in [
        (200, None),
        (400, Some(-32602)),
        (401, Some(-32602)),
        (500, Some(-32603)),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/repos/fixture/o/r/issues/7"))
            .and(header("authorization", "Bearer synthetic-token"))
            .respond_with(
                ResponseTemplate::new(status).set_body_json(json!({"title":"fixture issue"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let mut wire = Wire::new(config(&server.uri()));
        wire.initialize("2025-06-18").await;
        let frame = wire.request("tools/call", json!({"name":"get_issue","arguments":{"forge":"fixture","owner":"o","repo":"r","index":"7"}})).await;
        if let Some(code) = code {
            assert_error(&frame, code);
            if status == 401 {
                assert_eq!(frame["error"]["message"], "authentication failed");
            }
        } else {
            assert_eq!(
                frame,
                json!({"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{\"title\":\"fixture issue\"}"}],"isError":false}})
            );
        }
        wire.finish(true).await;
    }
}

#[tokio::test]
async fn eof_before_initialization_is_bounded() {
    let mut wire = Wire::new(config("http://fixture.invalid"));
    wire.finish(false).await;
}

#[tokio::test]
async fn partial_input_eof_and_malformed_frame_recovery() {
    let mut wire = Wire::new(config("http://fixture.invalid"));
    wire.io
        .get_mut()
        .write_all(b"{\"jsonrpc\":")
        .await
        .expect("partial frame");
    wire.finish(false).await;

    let mut wire = Wire::new(config("http://fixture.invalid"));
    wire.initialize("2025-06-18").await;
    wire.io
        .get_mut()
        .write_all(b"not json\n")
        .await
        .expect("malformed frame");
    // rmcp 3.4 ignores an unparseable frame and accepts the next valid one.
    let response = wire.request("tools/list", json!({})).await;
    assert!(response["result"]["tools"].is_array());
    wire.finish(true).await;
}

#[tokio::test]
async fn unsupported_and_malformed_initialization() {
    let mut wire = Wire::new(config("http://fixture.invalid"));
    let init = wire.initialize("unknown-old-revision").await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    wire.finish(true).await;
    let mut wire = Wire::new(config("http://fixture.invalid"));
    wire.send(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":42}}),
    )
    .await;
    wire.finish(false).await;
}

#[tokio::test]
async fn forwarder_stops_during_idle_headers_or_body() {
    for send_headers in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener");
        let url = format!("http://{}", listener.local_addr().expect("fixture address"));
        let mut wire = Wire::new(config(&url));
        wire.initialize("2025-06-18").await;
        let (socket, _) = tokio::time::timeout(DEADLINE, listener.accept())
            .await
            .expect("forwarder did not connect")
            .expect("accept");
        let mut socket = BufReader::new(socket);
        loop {
            let mut line = String::new();
            tokio::time::timeout(DEADLINE, socket.read_line(&mut line))
                .await
                .expect("request timeout")
                .expect("request headers");
            if line == "\r\n" {
                break;
            }
        }
        if send_headers {
            socket.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await.expect("SSE headers");
        }
        wire.finish(true).await;
        let mut line = String::new();
        assert_eq!(
            tokio::time::timeout(DEADLINE, socket.read_line(&mut line))
                .await
                .expect("forwarder retained idle HTTP connection after peer closed")
                .expect("HTTP EOF"),
            0
        );
    }
}

#[tokio::test]
async fn cancellation_keeps_session_usable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/fixture/o/r/issues/7"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(30))
                .set_body_json(json!({})),
        )
        .mount(&server)
        .await;
    let mut wire = Wire::new(config(&server.uri()));
    wire.initialize("2025-06-18").await;
    wire.send(json!({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"get_issue","arguments":{"forge":"fixture","owner":"o","repo":"r","index":7}}})).await;
    tokio::time::timeout(DEADLINE, async {
        loop {
            if server
                .received_requests()
                .await
                .expect("requests")
                .iter()
                .any(|request| request.url.path().ends_with("/issues/7"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("call did not start");
    wire.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99,"reason":"fixture cancellation"}})).await;
    assert!(wire.request("tools/list", json!({})).await["result"]["tools"].is_array());
    wire.finish(true).await;
}

#[tokio::test]
async fn gateway_forwarders_keep_identity_and_resume_once() {
    let servers = [MockServer::start().await, MockServer::start().await];
    let mut settings = config(&servers[0].uri());
    settings.channel_startup_spike = true;
    settings.gateways.clear();
    for (i, server) in servers.iter().enumerate() {
        let token = format!("synthetic-token-{i}");
        settings.gateways.push(GatewayConfig {
            name: format!("fixture-{i}"),
            token: token.clone(),
            url: server.uri(),
        });
        let event = json!({"kind":"issue","content":format!("fixture-{i}"),"meta":{"forge_alias":format!("fixture-{i}"),"owner":"o","repo":"r","event_kind":"issue","action":"opened","issue":7,"delivery_id":format!("delivery-{i}")}});
        Mock::given(method("GET"))
            .and(path("/api/v1/agent/events"))
            .and(header("authorization", format!("Bearer {token}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(format!("id: delivery-{i}\ndata: {event}\n\n")),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/agent/events"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(header("last-event-id", format!("delivery-{i}")))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(server)
            .await;
    }
    let mut wire = Wire::new(settings);
    wire.initialize("2025-06-18").await;
    wire.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .await;
    let mut deliveries = Vec::new();
    for _ in 0..3 {
        let frame = wire.receive().await;
        assert_eq!(frame["method"], "notifications/claude/channel");
        deliveries.push(
            frame["params"]["meta"]["delivery_id"]
                .as_str()
                .expect("delivery")
                .to_owned(),
        );
    }
    deliveries.sort();
    assert_eq!(deliveries, ["delivery-0", "delivery-1", "startup-spike"]);
    tokio::time::timeout(DEADLINE, async {
        loop {
            if servers[0]
                .received_requests()
                .await
                .expect("requests")
                .len()
                >= 2
                && servers[1]
                    .received_requests()
                    .await
                    .expect("requests")
                    .len()
                    >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("forwarders did not reconnect");
    wire.finish(true).await;
    // Both forwarders are in their retry backoff when the peer closes.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let mut subscribers = Vec::new();
    for server in &servers {
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2, "duplicate forwarder or retry after EOF");
        let ids: Vec<_> = requests
            .iter()
            .map(|request| {
                request
                    .url
                    .query_pairs()
                    .find(|(key, _)| key == "subscriber_id")
                    .expect("subscriber id")
                    .1
                    .into_owned()
            })
            .collect();
        assert_eq!(ids[0], ids[1], "subscriber identity must survive reconnect");
        subscribers.push(ids[0].clone());
    }
    assert_ne!(subscribers[0], subscribers[1]);
}

#[tokio::test]
async fn baseline_optional_arguments_and_write_body() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/repos/fixture/o/r/issues/1"))
        .and(header("authorization", "Bearer synthetic-token"))
        .and(wiremock::matchers::body_json(json!({"title":"fixture"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"number":1})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agent/info"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"forges":[{"alias":"fixture"}]})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let mut wire = Wire::new(config(&server.uri()));
    wire.initialize("2025-06-18").await;
    for body in [None, Some(Value::Null)] {
        let mut args = json!({"forge":"fixture","owner":"o","repo":"r","index":1,"title":"fixture","extra":"ignored"});
        if let Some(body) = body {
            args["body"] = body;
        }
        let result = wire
            .request(
                "tools/call",
                json!({"name":"update_issue","arguments":args}),
            )
            .await;
        assert_eq!(result["result"]["content"][0]["text"], "{\"number\":1}");
        assert!(result["result"].get("structuredContent").is_none());
    }
    for arguments in [None, Some(json!({}))] {
        let mut params = json!({"name":"forge_info"});
        if let Some(arguments) = arguments {
            params["arguments"] = arguments;
        }
        let response = wire.request("tools/call", params).await;
        let info: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("info");
        assert_eq!(info["forges"], json!([{"alias":"fixture"}]));
        assert_eq!(info["git_token"], "synthetic-token");
    }
    wire.finish(true).await;
}

#[tokio::test]
async fn baseline_channel_and_polling() {
    for channels in [false, true] {
        let server = MockServer::start().await;
        let event = json!({"kind":"change_request","content":"fixture event","meta":{"forge_alias":"fixture","owner":"o","repo":"r","event_kind":"change_request","action":"opened","change_request":7,"head_sha":"abc","delivery_id":"delivery"}});
        Mock::given(method("GET"))
            .and(path("/api/v1/agent/events"))
            .and(header("authorization", "Bearer synthetic-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(format!(
                        "event: change_request\nid: fixture:delivery\ndata: {event}\n\n"
                    )),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        let mut settings = config(&server.uri());
        settings.enable_channels = channels;
        let mut wire = Wire::new(settings);
        let init = wire.initialize("2025-06-18").await;
        if channels {
            assert_eq!(
                init["result"]["capabilities"]["experimental"],
                json!({"claude/channel":{}})
            );
        }
        // Preserve observed behavior: notifications are sent even with channels
        // disabled; that option currently controls advertised capabilities.
        let notification = wire.receive().await;
        assert_eq!(notification["method"], "notifications/claude/channel");
        assert_eq!(notification["params"]["content"], "fixture event");
        assert_eq!(notification["params"]["meta"]["forge"], "fixture");
        assert!(notification["params"]["meta"].get("forge_alias").is_none());
        let first = wire
            .request("tools/call", json!({"name":"poll_events"}))
            .await;
        let events: Value = serde_json::from_str(
            first["result"]["content"][0]["text"]
                .as_str()
                .expect("text"),
        )
        .expect("events");
        assert_eq!(events.as_array().expect("array").len(), 1);
        assert_eq!(events[0]["meta"]["forge_alias"], "fixture");
        let second = wire
            .request("tools/call", json!({"name":"poll_events"}))
            .await;
        assert_eq!(second["result"]["content"][0]["text"], "[]");
        wire.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        wire.finish(true).await;
    }
}

#[tokio::test]
async fn stdio_binary_protocol_and_eof() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/fixture/o/r/contents/README.md"))
        .and(header("authorization", "Bearer synthetic-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"content":"fixture contents","path":"README.md","git_ref":"main"}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_transport"))
        .env_clear()
        .env("FORGE_MCP_TOKEN", "synthetic-token")
        .args(["--gateway-url", &server.uri()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shim");
    let mut input = child.stdin.take().expect("stdin");
    let mut output = BufReader::new(child.stdout.take().expect("stdout"));
    for (id, method, params) in [
        (
            1,
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"stdio-fixture","version":"0"}}),
        ),
        (2, "tools/list", json!({})),
        (
            3,
            "tools/call",
            json!({"name":"read_repository_file","arguments":{"forge":"fixture","owner":"o","repo":"r","path":"README.md","git_ref":"main"}}),
        ),
    ] {
        input
            .write_all(
                format!(
                    "{}\n",
                    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut line = String::new();
        tokio::time::timeout(DEADLINE, output.read_line(&mut line))
            .await
            .expect("stdio timeout")
            .expect("read");
        let frame: Value = serde_json::from_str(&line).expect("only protocol frames on stdout");
        assert_eq!(frame["id"], id);
        assert!(frame.get("error").is_none(), "{frame}");
        if id == 1 {
            input
                .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
                .await
                .expect("initialized");
        }
        if id == 3 {
            assert_eq!(frame["result"]["content"][0]["text"], "fixture contents");
        }
    }
    drop(input);
    assert!(
        tokio::time::timeout(DEADLINE, child.wait())
            .await
            .expect("stdio shutdown timeout")
            .expect("exit")
            .success()
    );
    let mut remaining = String::new();
    assert_eq!(
        output.read_line(&mut remaining).await.expect("stdout EOF"),
        0
    );
}

#[tokio::test]
async fn pull_listing_schema_and_all_forwarding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agent/info"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"forges":[{"alias":"fixture","type":"forgejo"}]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/repos/fixture/o/r/pulls"))
        .and(wiremock::matchers::query_param("state", "all"))
        .and(header("authorization", "Bearer synthetic-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"index":1,"state":"Open"},{"index":2,"state":"Closed"},{"index":3,"state":"Merged"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    let mut wire = Wire::new(config(&server.uri()));
    wire.initialize("2025-06-18").await;
    let catalog = wire.request("tools/list", json!({})).await;
    let tool = catalog["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|tool| tool["name"] == "list_change_requests")
        .expect("tool");
    let schema = tool["inputSchema"].to_string();
    for state in ["open", "closed", "merged", "all"] {
        assert!(schema.contains(&format!("\"{state}\"")));
    }
    assert!(schema.contains("enum"));
    assert!(
        tool["description"]
            .as_str()
            .expect("description")
            .contains("never returns a prefix")
    );
    let result = wire
        .request(
            "tools/call",
            json!({"name":"list_change_requests","arguments":{
                "forge":"fixture","owner":"o","repo":"r","state":"all"
            }}),
        )
        .await;
    assert_eq!(result["result"]["isError"], false);
    let pulls: Value = serde_json::from_str(
        result["result"]["content"][0]["text"]
            .as_str()
            .expect("text"),
    )
    .expect("array");
    assert_eq!(pulls.as_array().expect("array").len(), 3);
    for invalid in ["invalid", "ALL", ""] {
        let result = wire
            .request(
                "tools/call",
                json!({"name":"list_change_requests","arguments":{
                    "forge":"fixture","owner":"o","repo":"r","state":invalid
                }}),
            )
            .await;
        assert_error(&result, -32602);
    }
    wire.finish(true).await;
}
