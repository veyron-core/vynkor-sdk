//! Integration test: the SDK's WebSocket client against the REAL kernel WS
//! gateway (D-05 acceptance: "an SDK plugin connects to the WS endpoint,
//! registers, and round-trips actions").
//!
//! Requires a built `vyn` binary. Located via `VYN_BIN`, falling back to
//! the sibling checkout `../veyron/target/{debug,release}/vyn`. When no
//! binary exists the tests skip with a note — build the kernel first
//! (`cargo build --manifest-path ../veyron/Cargo.toml`).

use prost::Message;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::timeout;
use vynkor_sdk::frame_mac::compute_tag;
use vynkor_sdk::proto::{
    envelope, ActionRequest, ActionResponse, ActionStatus, Envelope, PluginManifest,
};
use vynkor_sdk::{VeyronClient, VeyronError};

const WS_GATEWAY: &str = "/ws";
const SECRET_32: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

fn kernel_bin() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VYN_BIN") {
        return Some(PathBuf::from(p));
    }
    ["../veyron/target/debug/vyn", "../veyron/target/release/vyn"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

struct KernelProc {
    // Held only for its kill_on_drop side-effect (SIGKILL on test exit).
    _child: tokio::process::Child,
    port: u16,
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Start a real kernel binary with the WS gateway on an ephemeral port.
async fn spawn_kernel(bin: PathBuf, jwt_secret: Option<&str>) -> KernelProc {
    let port = free_port().await;
    let dir = std::env::temp_dir().join(format!("veyron_ws_it_{}_{port}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dir = dir.to_string_lossy().into_owned();

    let mut yaml = format!(
        "port: {port}\n\
         log_level: info\n\
         data_dir: {dir}\n\
         socket_path: {dir}/vyn.sock\n\
         pid_file: {dir}/vyn.pid\n\
         log_file: {dir}/vyn.log\n\
         tls: false\n\
         allow_no_auth: {}\n",
        jwt_secret.is_none()
    );
    if let Some(secret) = jwt_secret {
        yaml.push_str(&format!("jwt_secret: \"{secret}\"\n"));
    }
    let config_path = format!("{dir}/config.yaml");
    std::fs::write(&config_path, yaml).unwrap();

    let child = Command::new(bin)
        .arg("start")
        .arg("--foreground")
        .arg("--config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn vyn");
    KernelProc {
        _child: child,
        port,
    }
}

async fn connect_ws_retry(url: &str, token: &str, secret: Option<&[u8]>) -> VeyronClient {
    for attempt in 0..100 {
        match VeyronClient::connect_ws(url, token, secret).await {
            Ok(client) => return client,
            Err(e) if attempt < 99 => {
                let _ = e;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("ws connect to real gateway failed: {e}"),
        }
    }
    unreachable!()
}

/// Mint an HS256 JWT for `plugin_id` using the SDK's own HMAC primitive
/// (compute_tag = HMAC-SHA256 over secret || message). Works because the
/// kernel's validator is plain `jsonwebtoken` HS256 with `exp` validated.
fn mint_jwt(plugin_id: &str, secret: &[u8]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let claims = format!(
        r#"{{"sub":"{plugin_id}","permissions":[],"ipc_targets":[],"exp":{},"iat":{}}}"#,
        now + 3600,
        now
    );
    let signing_input = format!(
        "{}.{}",
        b64url(header.as_bytes()),
        b64url(claims.as_bytes())
    );
    let key: [u8; 32] = secret.try_into().expect("jwt secret must be 32 bytes");
    let sig = compute_tag(&key, signing_input.as_bytes(), &[]);
    format!("{signing_input}.{}", b64url(&sig))
}

/// Unpadded base64url, the JWT encoding.
fn b64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        out.push(ALPHABET[(b[0] >> 2) as usize] as char);
        out.push(ALPHABET[((b[0] & 0x03) << 4 | b[1] >> 4) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((b[1] & 0x0F) << 2 | b[2] >> 6) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b[2] & 0x3F) as usize] as char);
        }
    }
    out
}

#[tokio::test]
async fn ws_sdk_plugin_registers_and_roundtrips_action() {
    let Some(bin) = kernel_bin() else {
        eprintln!("skipping: vyn binary not found — set VYN_BIN or build ../veyron first");
        return;
    };
    let kernel = spawn_kernel(bin, None).await;
    let url = format!("ws://127.0.0.1:{}{WS_GATEWAY}", kernel.port);

    // Two SDK plugins over WS; A sends B an ActionRequest, B answers.
    let mut client_a = connect_ws_retry(&url, "", None).await;
    client_a
        .register_full(
            "ws-plugin-a",
            "1.0.0",
            PluginManifest {
                permissions: vec!["PERMISSION_IPC_SEND".to_string()],
                ipc_targets: vec!["ws-plugin-b".to_string()],
                ..Default::default()
            },
            "",
        )
        .await
        .expect("register A failed");
    assert!(
        !client_a.is_secured(),
        "unsecured kernel must not enable MAC"
    );

    let mut client_b = connect_ws_retry(&url, "", None).await;
    client_b
        .register_full(
            "ws-plugin-b",
            "1.0.0",
            PluginManifest {
                permissions: vec!["PERMISSION_IPC_SEND".to_string()],
                ipc_targets: vec!["ws-plugin-a".to_string()],
                ..Default::default()
            },
            "",
        )
        .await
        .expect("register B failed");

    // Ping round-trip through the real gateway.
    timeout(Duration::from_secs(2), client_a.ping())
        .await
        .expect("ping timed out")
        .expect("ping failed");

    // A → B: raw ActionRequest envelope.
    let req_env = Envelope {
        payload: Some(envelope::Payload::ActionRequest(ActionRequest {
            action_id: "ws-act-001".to_string(),
            action: "echo".to_string(),
            params_json: br#"{"msg":"hello"}"#.to_vec(),
            timeout_ms: 3000,
            streaming: false,
            ..Default::default()
        })),
        ..Default::default()
    };
    let mut req_payload = Vec::new();
    req_env.encode(&mut req_payload).unwrap();
    client_a
        .send_raw("ws-plugin-b", req_payload)
        .await
        .expect("send ActionRequest failed");

    let received = timeout(Duration::from_secs(2), client_b.recv())
        .await
        .expect("recv timed out")
        .expect("recv failed");
    let action_id = match received.payload {
        Some(envelope::Payload::ActionRequest(ar)) => {
            assert_eq!(ar.action, "echo");
            assert_eq!(ar.action_id, "ws-act-001");
            ar.action_id
        }
        other => panic!("expected ActionRequest, got {other:?}"),
    };

    // B → A: ActionResponse.
    let resp_env = Envelope {
        payload: Some(envelope::Payload::ActionResponse(ActionResponse {
            action_id,
            status: ActionStatus::ActionOk as i32,
            data_json: br#"{"echo":"hello"}"#.to_vec(),
            error: String::new(),
        })),
        ..Default::default()
    };
    let mut resp_payload = Vec::new();
    resp_env.encode(&mut resp_payload).unwrap();
    client_b
        .send_raw("ws-plugin-a", resp_payload)
        .await
        .expect("send ActionResponse failed");

    let response = timeout(Duration::from_secs(2), client_a.recv())
        .await
        .expect("response timed out")
        .expect("response failed");
    match response.payload {
        Some(envelope::Payload::ActionResponse(resp)) => {
            assert_eq!(resp.action_id, "ws-act-001");
            assert_eq!(resp.status, ActionStatus::ActionOk as i32);
            assert_eq!(resp.data_json, br#"{"echo":"hello"}"#);
        }
        other => panic!("expected ActionResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn ws_sdk_secured_jwt_and_mac_roundtrip() {
    let Some(bin) = kernel_bin() else {
        eprintln!("skipping: vyn binary not found — set VYN_BIN or build ../veyron first");
        return;
    };
    let kernel = spawn_kernel(bin, Some(std::str::from_utf8(SECRET_32).unwrap())).await;
    let url = format!("ws://127.0.0.1:{}{WS_GATEWAY}", kernel.port);

    let token = mint_jwt("ws-sec-plugin", SECRET_32);
    let mut client = connect_ws_retry(&url, &token, Some(SECRET_32)).await;

    let ack = client
        .register_full("ws-sec-plugin", "1.0.0", PluginManifest::default(), &token)
        .await
        .expect("secured register failed");
    assert!(ack.accepted, "rejected: {}", ack.reject_reason);
    assert!(
        !ack.session_nonce.is_empty(),
        "secured kernel must mint a nonce"
    );
    assert!(client.is_secured(), "session key not derived from nonce");

    // Ping is MAC-tagged by the client and the Pong must verify on the
    // client side too — full HMAC round-trip through the real gateway.
    timeout(Duration::from_secs(2), client.ping())
        .await
        .expect("secured ping timed out")
        .expect("secured ping failed");

    // A bad token must be rejected at the WS handshake.
    let rejected = timeout(
        Duration::from_secs(2),
        VeyronClient::connect_ws(&url, "garbage-token", Some(SECRET_32)),
    )
    .await
    .expect("rejected handshake must not hang");
    assert!(
        matches!(rejected, Err(VeyronError::Io(_))),
        "bad token must fail the handshake"
    );
}
