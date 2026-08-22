//! WS transport tests for the SDK client against a scripted in-process
//! "fake kernel" WebSocket gateway (no real kernel needed): registration,
//! frame-MAC enable, action round-trips, the R5-03 gateway limits (no
//! compression / fragmentation outbound, raw binary passes) and reconnect.
//!
//! The full kernel-in-the-loop coverage lives in `tests/ws_kernel_integration.rs`.

use futures_util::{SinkExt, StreamExt};
use prost::Message;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use vynkor_sdk::frame_mac::{compute_tag, derive_session_key, verify_tag};
use vynkor_sdk::framing::{
    read_frame, serialize_header, Frame, COMPRESS_THRESHOLD, FLAG_MAC_PRESENT, FLAG_RAW_BINARY,
};
use vynkor_sdk::proto::{
    envelope, ActionResponse, ActionStatus, Envelope, Ping, PluginManifest, PluginRegisterAck, Pong,
};
use vynkor_sdk::{VynkorClient, VynkorError};

const FAKE_SECRET: &[u8] = b"ws-fake-secret-32-bytes-minimum";
const NONCE: &[u8; 16] = b"0123456789abcdef";

type FakeWs = WebSocketStream<TcpStream>;

fn ws_url(port: u16) -> String {
    format!("ws://127.0.0.1:{port}/ws")
}

/// Bind an ephemeral port for the fake gateway.
async fn spawn_listener() -> (u16, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (port, listener)
}

/// Upgrade a TCP stream to WS, selecting the `vynkor` subprotocol like the
/// real gateway (axum `ws.protocols(["veyron"])`) so the client's offer is
/// accepted.
#[allow(clippy::result_large_err)] // tungstenite::Error embeds a Response
async fn accept_ws_stream(stream: TcpStream) -> FakeWs {
    use tokio_tungstenite::tungstenite::http::{header, Request, Response};
    accept_hdr_async(stream, |_req: &Request<()>, mut resp: Response<()>| {
        resp.headers_mut()
            .insert(header::SEC_WEBSOCKET_PROTOCOL, "veyron".parse().unwrap());
        Ok(resp)
    })
    .await
    .unwrap()
}

async fn accept_ws(listener: &TcpListener) -> FakeWs {
    let (stream, _) = listener.accept().await.unwrap();
    accept_ws_stream(stream).await
}

fn make_target(target: &str) -> [u8; 32] {
    let mut t = [0u8; 32];
    let b = target.as_bytes();
    t[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
    t
}

/// Serialize an envelope into a frame, tagging with `key` when secured.
fn make_frame(target: &str, env: &Envelope, key: Option<&[u8; 32]>) -> Frame {
    let mut buf = Vec::new();
    env.encode(&mut buf).unwrap();
    let flags = if key.is_some() { FLAG_MAC_PRESENT } else { 0 };
    let mut frame = Frame {
        magic: 0x5652,
        flags,
        length: buf.len() as u32,
        target: make_target(target),
        crc32: crc32fast::hash(&buf),
        payload: buf.into(),
        mac: None,
    };
    if let Some(k) = key {
        let header = serialize_header(&frame);
        frame.mac = Some(compute_tag(k, &header, &frame.payload));
    }
    frame
}

fn frame_to_ws_bytes(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&serialize_header(frame));
    out.extend_from_slice(&frame.payload);
    if let Some(tag) = &frame.mac {
        out.extend_from_slice(tag);
    }
    out
}

async fn send_ws_frame(ws: &mut FakeWs, frame: &Frame) {
    ws.send(WsMessage::Binary(frame_to_ws_bytes(frame)))
        .await
        .unwrap();
}

async fn read_ws_frame(ws: &mut FakeWs) -> Frame {
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("fake kernel recv timed out")
        .expect("fake kernel stream ended")
        .expect("fake kernel ws error");
    match msg {
        WsMessage::Binary(data) => {
            let mut cursor: &[u8] = &data;
            read_frame(&mut cursor).await.unwrap()
        }
        other => panic!("fake kernel expected binary frame, got {other:?}"),
    }
}

fn decode(frame: &Frame) -> Envelope {
    Envelope::decode(frame.payload.as_ref()).expect("decode envelope")
}

fn ack_envelope(nonce: Option<&[u8]>) -> Envelope {
    Envelope {
        payload: Some(envelope::Payload::PluginRegisterAck(PluginRegisterAck {
            accepted: true,
            session_nonce: nonce.unwrap_or(&[]).to_vec(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[tokio::test]
async fn ws_client_registers_and_roundtrips_action() {
    let (port, listener) = spawn_listener().await;

    let kernel = tokio::spawn(async move {
        let mut ws = accept_ws(&listener).await;

        // Registration → ack (no nonce: unsecured kernel).
        let reg = read_ws_frame(&mut ws).await;
        match decode(&reg).payload {
            Some(envelope::Payload::PluginRegister(r)) => {
                assert_eq!(r.plugin_id, "ws-test");
                assert_eq!(r.version, "1.0.0");
            }
            other => panic!("expected register, got {other:?}"),
        }
        send_ws_frame(&mut ws, &make_frame("ws-test", &ack_envelope(None), None)).await;

        // Ping → Pong.
        let ping = read_ws_frame(&mut ws).await;
        match decode(&ping).payload {
            Some(envelope::Payload::Ping(p)) => assert_eq!(p.timestamp, 42),
            other => panic!("expected ping, got {other:?}"),
        }
        let pong = Envelope {
            payload: Some(envelope::Payload::Pong(Pong {
                original_timestamp: 42,
                server_timestamp: 43,
            })),
            ..Default::default()
        };
        send_ws_frame(&mut ws, &make_frame("ws-test", &pong, None)).await;

        // ActionRequest → ActionResponse.
        let req = read_ws_frame(&mut ws).await;
        let action_id = match decode(&req).payload {
            Some(envelope::Payload::ActionRequest(ar)) => {
                assert_eq!(ar.action, "echo");
                ar.action_id
            }
            other => panic!("expected action request, got {other:?}"),
        };
        let resp = Envelope {
            payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                action_id,
                status: ActionStatus::ActionOk as i32,
                data_json: b"ok".to_vec(),
                error: String::new(),
            })),
            ..Default::default()
        };
        send_ws_frame(&mut ws, &make_frame("ws-test", &resp, None)).await;
    });

    let mut client = VynkorClient::connect_ws(&ws_url(port), "", None)
        .await
        .expect("ws connect failed");
    let ack = client
        .register_full("ws-test", "1.0.0", PluginManifest::default(), "")
        .await
        .expect("register failed");
    assert!(ack.accepted);

    let ping = Envelope {
        payload: Some(envelope::Payload::Ping(Ping { timestamp: 42 })),
        ..Default::default()
    };
    client.send("kernel", ping).await.unwrap();
    let pong = client.recv().await.unwrap();
    match pong.payload {
        Some(envelope::Payload::Pong(p)) => assert_eq!(p.original_timestamp, 42),
        other => panic!("expected pong, got {other:?}"),
    }

    let resp = client
        .send_action("echo", b"{}", 2000)
        .await
        .expect("action round-trip failed");
    assert_eq!(resp.status, ActionStatus::ActionOk as i32);
    assert_eq!(resp.data_json, b"ok");

    kernel.await.unwrap();
}

#[tokio::test]
async fn ws_secured_registration_enables_mac() {
    let (port, listener) = spawn_listener().await;

    let kernel = tokio::spawn(async move {
        let mut ws = accept_ws(&listener).await;

        let reg = read_ws_frame(&mut ws).await;
        match decode(&reg).payload {
            Some(envelope::Payload::PluginRegister(r)) => assert_eq!(r.plugin_id, "ws-sec"),
            other => panic!("expected register, got {other:?}"),
        }
        send_ws_frame(
            &mut ws,
            &make_frame("ws-sec", &ack_envelope(Some(NONCE)), None),
        )
        .await;

        // The next frame must carry a MAC derived from secret+nonce+id.
        let secured = read_ws_frame(&mut ws).await;
        assert_ne!(secured.flags & FLAG_MAC_PRESENT, 0, "MAC flag missing");
        let key = derive_session_key(FAKE_SECRET, NONCE, "ws-sec");
        let tag = secured.mac.expect("tag missing");
        assert!(
            verify_tag(&key, &serialize_header(&secured), &secured.payload, &tag),
            "MAC verification failed on kernel side"
        );
    });

    let mut client = VynkorClient::connect_ws(&ws_url(port), "tok", Some(FAKE_SECRET))
        .await
        .expect("ws connect failed");
    let ack = client
        .register_full("ws-sec", "1.0.0", PluginManifest::default(), "tok")
        .await
        .expect("register failed");
    assert!(ack.accepted);
    assert!(client.is_secured(), "session key not derived from nonce");

    client.subscribe(vec!["*".into()]).await.unwrap();
    kernel.await.unwrap();
}

#[tokio::test]
async fn ws_large_payload_is_not_compressed_on_wire() {
    let (port, listener) = spawn_listener().await;

    let big = vec![0x42u8; COMPRESS_THRESHOLD + 1024];
    let expected = big.clone();

    let kernel = tokio::spawn(async move {
        let mut ws = accept_ws(&listener).await;
        let _reg = read_ws_frame(&mut ws).await;
        send_ws_frame(&mut ws, &make_frame("ws-big", &ack_envelope(None), None)).await;

        // R5-03: the gateway rejects FLAG_COMPRESSED inbound, so the WS
        // transport must never compress — even past the UDS threshold.
        let frame = read_ws_frame(&mut ws).await;
        assert_eq!(frame.flags & vynkor_sdk::framing::FLAG_COMPRESSED, 0);
        assert_eq!(frame.length as usize, expected.len());
        assert_eq!(&*frame.payload, expected);
    });

    let mut client = VynkorClient::connect_ws(&ws_url(port), "", None)
        .await
        .expect("ws connect failed");
    client
        .register_full("ws-big", "1.0.0", PluginManifest::default(), "")
        .await
        .expect("register failed");
    client.send_raw("peer", big).await.expect("send failed");
    kernel.await.unwrap();
}

#[tokio::test]
async fn ws_send_fragmented_is_rejected() {
    let (port, listener) = spawn_listener().await;

    // Hold an upgraded connection open so the client can connect.
    let held = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = accept_ws_stream(stream).await;
        while ws.next().await.is_some() {}
    });

    let mut client = VynkorClient::connect_ws(&ws_url(port), "", None)
        .await
        .expect("ws connect failed");

    // send_fragmented is rejected at the client before anything hits the wire.
    let err = client
        .send_fragmented("peer", &[1u8; 64], 10)
        .await
        .expect_err("fragmented send must fail over WS");
    match err {
        VynkorError::Internal(msg) => assert!(msg.contains("WebSocket"), "got: {msg}"),
        other => panic!("expected Internal error, got {other:?}"),
    }
    held.abort();
}

#[tokio::test]
async fn ws_raw_binary_passes() {
    let (port, listener) = spawn_listener().await;

    let pcm = vec![0x01u8, 0x02, 0x03, 0x04];
    let expected = pcm.clone();

    let kernel = tokio::spawn(async move {
        let mut ws = accept_ws(&listener).await;
        let _reg = read_ws_frame(&mut ws).await;
        send_ws_frame(&mut ws, &make_frame("ws-audio", &ack_envelope(None), None)).await;

        // FLAG_RAW_BINARY is the one payload class the gateway forwards as-is.
        let frame = read_ws_frame(&mut ws).await;
        assert_ne!(frame.flags & FLAG_RAW_BINARY, 0);
        assert_eq!(&*frame.payload, expected);
    });

    let mut client = VynkorClient::connect_ws(&ws_url(port), "", None)
        .await
        .expect("ws connect failed");
    client
        .register_full("ws-audio", "1.0.0", PluginManifest::default(), "")
        .await
        .expect("register failed");
    client
        .send_raw_audio("peer", pcm)
        .await
        .expect("raw audio send failed");
    kernel.await.unwrap();
}

#[tokio::test]
async fn ws_reconnect_reregisters_and_reenables_mac() {
    let (port, listener) = spawn_listener().await;

    let kernel = tokio::spawn(async move {
        // First connection: register, MAC-verify the ping, then drop.
        {
            let mut ws = accept_ws(&listener).await;
            let reg = read_ws_frame(&mut ws).await;
            assert!(matches!(
                decode(&reg).payload,
                Some(envelope::Payload::PluginRegister(_))
            ));
            send_ws_frame(
                &mut ws,
                &make_frame("ws-re", &ack_envelope(Some(NONCE)), None),
            )
            .await;

            let ping = read_ws_frame(&mut ws).await;
            let key1 = derive_session_key(FAKE_SECRET, NONCE, "ws-re");
            assert_ne!(ping.flags & FLAG_MAC_PRESENT, 0);
            let tag1 = ping.mac.expect("tag missing");
            assert!(verify_tag(
                &key1,
                &serialize_header(&ping),
                &ping.payload,
                &tag1
            ));
            // Reply MAC-tagged (the client verifies inbound tags too).
            let pong = Envelope {
                payload: Some(envelope::Payload::Pong(Pong {
                    original_timestamp: 1,
                    server_timestamp: 2,
                })),
                ..Default::default()
            };
            send_ws_frame(&mut ws, &make_frame("ws-re", &pong, Some(&key1))).await;
            // Drop: connection 1 is gone.
        }

        // Second connection: fresh register must re-derive a fresh key.
        let fresh_nonce: [u8; 16] = *b"fedcba9876543210";
        let mut ws = accept_ws(&listener).await;
        let reg = read_ws_frame(&mut ws).await;
        assert!(matches!(
            decode(&reg).payload,
            Some(envelope::Payload::PluginRegister(_))
        ));
        send_ws_frame(
            &mut ws,
            &make_frame("ws-re", &ack_envelope(Some(&fresh_nonce)), None),
        )
        .await;

        let ping = read_ws_frame(&mut ws).await;
        let key2 = derive_session_key(FAKE_SECRET, &fresh_nonce, "ws-re");
        assert_ne!(ping.flags & FLAG_MAC_PRESENT, 0);
        let tag2 = ping.mac.expect("tag missing");
        assert!(verify_tag(
            &key2,
            &serialize_header(&ping),
            &ping.payload,
            &tag2
        ));
        let pong = Envelope {
            payload: Some(envelope::Payload::Pong(Pong {
                original_timestamp: 2,
                server_timestamp: 3,
            })),
            ..Default::default()
        };
        send_ws_frame(&mut ws, &make_frame("ws-re", &pong, Some(&key2))).await;
    });

    // Connection 1.
    let mut client = VynkorClient::connect_ws(&ws_url(port), "tok", Some(FAKE_SECRET))
        .await
        .expect("ws connect failed");
    let ack = client
        .register_full("ws-re", "1.0.0", PluginManifest::default(), "tok")
        .await
        .expect("register failed");
    assert!(ack.accepted);
    assert!(client.is_secured());

    let ping = Envelope {
        payload: Some(envelope::Payload::Ping(Ping { timestamp: 1 })),
        ..Default::default()
    };
    client.send("kernel", ping).await.unwrap();
    let pong = client.recv().await.unwrap();
    assert!(matches!(pong.payload, Some(envelope::Payload::Pong(_))));

    // Kernel dropped connection 1 — the next recv must surface the disconnect.
    let err = client
        .recv_timeout(Duration::from_secs(2))
        .await
        .expect_err("disconnect not surfaced");
    assert!(matches!(err, VynkorError::Io(_)), "got {err:?}");

    // Reconnect: fresh connect + register, MAC re-derived from the new nonce.
    let mut client = VynkorClient::connect_ws(&ws_url(port), "tok", Some(FAKE_SECRET))
        .await
        .expect("reconnect failed");
    let ack = client
        .register_full("ws-re", "1.0.0", PluginManifest::default(), "tok")
        .await
        .expect("re-register failed");
    assert!(ack.accepted);
    assert!(client.is_secured(), "MAC not re-enabled after reconnect");

    let ping = Envelope {
        payload: Some(envelope::Payload::Ping(Ping { timestamp: 2 })),
        ..Default::default()
    };
    client.send("kernel", ping).await.unwrap();
    let pong = client.recv().await.unwrap();
    assert!(matches!(pong.payload, Some(envelope::Payload::Pong(_))));

    kernel.await.unwrap();
}
