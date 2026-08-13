//! Async client for the Veyron kernel IPC socket.
//!
//! [`VeyronClient`] speaks the full Veyron wire protocol as specified in
//! `docs/FRAMING.md`:
//!
//! - **Framing** — 44-byte header (magic, flags, length, target, crc32) via the
//!   kernel framing layer (re-exported in [`crate::framing`]).
//! - **Compression** (`FLAG_COMPRESSED`) — outbound payloads ≥ 64 KiB are
//!   transparently zstd-compressed by `write_frame_raw`; inbound frames are
//!   decompressed and normalized by `read_frame`.
//! - **MAC** (`FLAG_MAC_PRESENT`) — on secured kernels every frame carries an
//!   HMAC-SHA256 tag over the *plaintext* header + payload, keyed by an
//!   HKDF-derived per-connection session key.
//! - **Fragmentation** (`FLAG_FRAGMENTED`) — large messages can be split into
//!   fragments with [`VeyronClient::send_fragmented`]; inbound fragments are
//!   reassembled transparently by [`VeyronClient::recv_frame`] with the same
//!   bounds the kernel enforces (64 streams, 1 MiB, 30 s).
//! - **Raw binary** (`FLAG_RAW_BINARY`) — audio frames bypass Protobuf; see
//!   [`VeyronClient::send_raw_audio`] and [`VeyronClient::recv_frame`].

use crate::framing::{read_frame, Frame, FLAG_FRAGMENTED, FLAG_MAC_PRESENT, FLAG_RAW_BINARY};
use prost::Message;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use veyron_wire::framing::{
    parse_frag_header, serialize_header, write_frame_raw, FRAG_HEADER_SIZE, MAX_PAYLOAD_SIZE,
};
use veyron_wire::mac::{compute_tag, derive_session_key, verify_tag};
use veyron_wire::proto::veyron::{
    envelope, ActionRequest, ActionRequestChunk, ActionResponse, ActionResponseChunk,
    AudioStreamChunk, Envelope, EventAck, EventPublish, EventPublishAck, KernelCommand,
    KernelCommandAck, Ping, PluginManifest, PluginRegister, PluginRegisterAck, SessionClose,
    Subscribe, Unsubscribe,
};
use veyron_wire::WireError as VeyronError;

/// Mirror of the kernel's inbound reassembly bounds (see `src/ipc/connection.rs`).
const MAX_REASSEMBLY_STREAMS: usize = 64;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Default request timeout when a caller passes `timeout_ms == 0`.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

static ACTION_SEQ: AtomicU64 = AtomicU64::new(0);

struct ReassemblyBuf {
    fragments: HashMap<u16, Vec<u8>>,
    total: u16,
    target: [u8; 32],
    flags: u16,
    first_seen: Instant,
    buffered_bytes: usize,
}

impl ReassemblyBuf {
    fn is_complete(&self) -> bool {
        self.fragments.len() == self.total as usize
    }

    fn reassemble(mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buffered_bytes);
        for seq in 0..self.total {
            if let Some(chunk) = self.fragments.remove(&seq) {
                out.extend_from_slice(&chunk);
            }
        }
        out
    }
}

/// Async connection to the Veyron kernel over a Unix domain socket.
///
/// Create with [`VeyronClient::connect`] (no auth) or
/// [`VeyronClient::connect_with_secret`] (secured kernel), then call
/// [`VeyronClient::register`] / [`VeyronClient::register_with_token`] before
/// any other traffic.
pub struct VeyronClient {
    read: OwnedReadHalf,
    write: OwnedWriteHalf,
    /// Shared JWT secret, needed to derive the frame-MAC key. None => no MAC.
    secret: Option<Vec<u8>>,
    /// Per-connection MAC key, set after a secured registration.
    session_key: Option<[u8; 32]>,
    /// Inbound fragment reassembly buffers, keyed by stream_id.
    reassembly: HashMap<u32, ReassemblyBuf>,
    /// Monotonic stream id source for [`VeyronClient::send_fragmented`].
    next_stream_id: u32,
}

impl VeyronClient {
    /// Connect to an unsecured kernel (started with `allow_no_auth: true`).
    pub async fn connect(socket_path: &str) -> Result<Self, VeyronError> {
        Self::connect_inner(socket_path, None).await
    }

    /// Connect with the shared JWT secret so the client can derive the frame-MAC
    /// key after registration (required to talk to a kernel started with auth).
    pub async fn connect_with_secret(
        socket_path: &str,
        secret: &[u8],
    ) -> Result<Self, VeyronError> {
        Self::connect_inner(socket_path, Some(secret.to_vec())).await
    }

    /// Connect using the standard environment:
    /// `VEYRON_SOCKET_PATH` (falls back to the per-user default path) and
    /// `VEYRON_JWT_SECRET` (optional; enables frame MACs when set).
    pub async fn connect_from_env() -> Result<Self, VeyronError> {
        let socket_path = std::env::var("VEYRON_SOCKET_PATH")
            .unwrap_or_else(|_| veyron_wire::socket::default_socket_path());
        match std::env::var("VEYRON_JWT_SECRET") {
            Ok(secret) if !secret.is_empty() => {
                Self::connect_with_secret(&socket_path, secret.as_bytes()).await
            }
            _ => Self::connect(&socket_path).await,
        }
    }

    /// Wrap an already-connected [`UnixStream`]. Useful for tests
    /// (`UnixStream::pair`) and custom transports.
    pub fn from_stream(stream: UnixStream, secret: Option<Vec<u8>>) -> Self {
        let (read, write) = stream.into_split();
        Self {
            read,
            write,
            secret,
            session_key: None,
            reassembly: HashMap::new(),
            next_stream_id: 1,
        }
    }

    async fn connect_inner(
        socket_path: &str,
        secret: Option<Vec<u8>>,
    ) -> Result<Self, VeyronError> {
        let stream = UnixStream::connect(socket_path)
            .await
            .map_err(VeyronError::Io)?;
        Ok(Self::from_stream(stream, secret))
    }

    /// True once a secured registration has derived the per-connection MAC key.
    pub fn is_secured(&self) -> bool {
        self.session_key.is_some()
    }

    // ── Registration ────────────────────────────────────────────────

    /// Register without a JWT (unsecured kernel only).
    pub async fn register(
        &mut self,
        plugin_id: &str,
        manifest: PluginManifest,
    ) -> Result<PluginRegisterAck, VeyronError> {
        self.register_with_token(plugin_id, manifest, "").await
    }

    /// Register presenting a JWT. On a secured kernel the ack carries a
    /// `session_nonce`; combined with the shared secret and plugin id it yields
    /// the frame-MAC key used for all subsequent frames.
    pub async fn register_with_token(
        &mut self,
        plugin_id: &str,
        manifest: PluginManifest,
        jwt_token: &str,
    ) -> Result<PluginRegisterAck, VeyronError> {
        self.register_full(plugin_id, "1.0.0", manifest, jwt_token)
            .await
    }

    /// Register with an explicit plugin version string.
    pub async fn register_full(
        &mut self,
        plugin_id: &str,
        version: &str,
        manifest: PluginManifest,
        jwt_token: &str,
    ) -> Result<PluginRegisterAck, VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::PluginRegister(PluginRegister {
                plugin_id: plugin_id.to_string(),
                version: version.to_string(),
                manifest: Some(manifest),
                jwt_token: jwt_token.to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        let response = self.recv().await?;
        match response.payload {
            Some(envelope::Payload::PluginRegisterAck(ack)) => {
                if let Some(secret) = &self.secret {
                    if !ack.session_nonce.is_empty() {
                        self.session_key =
                            Some(derive_session_key(secret, &ack.session_nonce, plugin_id));
                    }
                }
                Ok(ack)
            }
            Some(envelope::Payload::Error(err)) => Err(VeyronError::Internal(format!(
                "registration rejected: {} ({})",
                err.message, err.details
            ))),
            _ => Err(VeyronError::Internal("expected PluginRegisterAck".into())),
        }
    }

    // ── Sending ─────────────────────────────────────────────────────

    /// Encode and send a Protobuf [`Envelope`] to `target` ("kernel" or a
    /// peer plugin id).
    pub async fn send(&mut self, target: &str, envelope: Envelope) -> Result<(), VeyronError> {
        let mut payload = Vec::new();
        envelope
            .encode(&mut payload)
            .map_err(|_| VeyronError::Internal("encode failed".into()))?;
        self.send_raw(target, payload).await
    }

    /// Send a pre-encoded payload. Applies MAC when secured; payloads ≥ 64 KiB
    /// are transparently zstd-compressed by the framing layer.
    pub async fn send_raw(&mut self, target: &str, payload: Vec<u8>) -> Result<(), VeyronError> {
        self.send_raw_with_flags(target, 0, payload).await
    }

    /// Send a raw payload with explicit extra flags ORed into the frame header
    /// (e.g. [`FLAG_RAW_BINARY`]). MAC is added automatically when secured.
    pub async fn send_raw_with_flags(
        &mut self,
        target: &str,
        extra_flags: u16,
        payload: Vec<u8>,
    ) -> Result<(), VeyronError> {
        let base_flags = if self.session_key.is_some() {
            FLAG_MAC_PRESENT
        } else {
            0
        };
        let mut frame = build_frame(target, base_flags | extra_flags, payload);
        if let Some(key) = &self.session_key {
            let header = serialize_header(&frame);
            frame.mac = Some(compute_tag(key, &header, &frame.payload));
        }
        write_frame_raw(&mut self.write, &frame).await
    }

    /// Split `payload` into `FLAG_FRAGMENTED` frames of at most `chunk_size`
    /// data bytes each and send them on a fresh stream id. The kernel
    /// reassembles them into a single logical frame for `target`.
    ///
    /// Bounds mirror the kernel: total payload ≤ 1 MiB, ≤ 65 535 fragments.
    pub async fn send_fragmented(
        &mut self,
        target: &str,
        payload: &[u8],
        chunk_size: usize,
    ) -> Result<(), VeyronError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(VeyronError::PayloadTooLarge(payload.len()));
        }
        if chunk_size == 0 || chunk_size + FRAG_HEADER_SIZE > MAX_PAYLOAD_SIZE {
            return Err(VeyronError::Internal(format!(
                "invalid fragment chunk_size: {chunk_size}"
            )));
        }
        let total = payload.len().div_ceil(chunk_size).max(1);
        if total > u16::MAX as usize {
            return Err(VeyronError::Internal(format!(
                "payload needs {total} fragments; max is {}",
                u16::MAX
            )));
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1).max(1);
        let fragment_id = (stream_id & 0xFFFF) as u16;

        for (seq, chunk) in payload.chunks(chunk_size).enumerate() {
            let mut frag_payload = Vec::with_capacity(FRAG_HEADER_SIZE + chunk.len());
            frag_payload.extend_from_slice(&fragment_id.to_be_bytes());
            frag_payload.extend_from_slice(&(seq as u16).to_be_bytes());
            frag_payload.extend_from_slice(&(total as u16).to_be_bytes());
            frag_payload.extend_from_slice(&stream_id.to_be_bytes());
            frag_payload.extend_from_slice(chunk);
            self.send_raw_with_flags(target, FLAG_FRAGMENTED, frag_payload)
                .await?;
        }
        Ok(())
    }

    // ── Receiving ───────────────────────────────────────────────────

    /// Receive the next complete frame. Verifies the MAC on secured
    /// connections, reassembles fragmented messages, and returns raw-binary
    /// frames as-is (check `frame.flags & FLAG_RAW_BINARY`). Compressed frames
    /// arrive already decompressed and normalized by the framing layer.
    pub async fn recv_frame(&mut self) -> Result<Frame, VeyronError> {
        loop {
            let frame = read_frame(&mut self.read).await?;
            self.verify_frame_mac(&frame)?;
            if frame.flags & FLAG_FRAGMENTED != 0 {
                if let Some(complete) = self.absorb_fragment(frame)? {
                    return Ok(complete);
                }
                continue;
            }
            return Ok(frame);
        }
    }

    /// Receive and decode the next Protobuf [`Envelope`]. Errors on raw-binary
    /// frames; use [`VeyronClient::recv_frame`] when expecting audio.
    pub async fn recv(&mut self) -> Result<Envelope, VeyronError> {
        let frame = self.recv_frame().await?;
        if frame.flags & FLAG_RAW_BINARY != 0 {
            return Err(VeyronError::Internal(
                "received raw-binary frame; use recv_frame() for audio".into(),
            ));
        }
        Envelope::decode(frame.payload.as_ref()).map_err(VeyronError::Proto)
    }

    /// [`VeyronClient::recv`] bounded by `timeout`. Returns
    /// [`VeyronError::Timeout`] if nothing arrives in time.
    pub async fn recv_timeout(&mut self, timeout: Duration) -> Result<Envelope, VeyronError> {
        match tokio::time::timeout(timeout, self.recv()).await {
            Ok(result) => result,
            Err(_) => Err(VeyronError::Timeout),
        }
    }

    fn verify_frame_mac(&self, frame: &Frame) -> Result<(), VeyronError> {
        if let Some(key) = &self.session_key {
            let valid = frame.flags & FLAG_MAC_PRESENT != 0
                && match &frame.mac {
                    Some(tag) => {
                        let header = serialize_header(frame);
                        verify_tag(key, &header, &frame.payload, tag)
                    }
                    None => false,
                };
            if !valid {
                return Err(VeyronError::Internal(
                    "frame MAC verification failed".into(),
                ));
            }
        }
        Ok(())
    }

    /// Buffer one fragment; returns the reassembled frame when the set is
    /// complete. Enforces the kernel's bounds and errors (instead of silently
    /// growing) on violations.
    fn absorb_fragment(&mut self, frame: Frame) -> Result<Option<Frame>, VeyronError> {
        // Prune stale sets first so an abandoned stream cannot pin memory.
        self.reassembly
            .retain(|_, buf| buf.first_seen.elapsed() < REASSEMBLY_TIMEOUT);

        let hdr = parse_frag_header(&frame.payload)
            .ok_or_else(|| VeyronError::Internal("fragment header too short".into()))?;
        if hdr.total == 0 || hdr.sequence >= hdr.total {
            return Err(VeyronError::Internal(format!(
                "invalid fragment header: seq {} / total {}",
                hdr.sequence, hdr.total
            )));
        }
        if let Some(existing) = self.reassembly.get(&hdr.stream_id) {
            if existing.total != hdr.total {
                self.reassembly.remove(&hdr.stream_id);
                return Err(VeyronError::Internal(
                    "fragment total mismatch within stream".into(),
                ));
            }
        } else if self.reassembly.len() >= MAX_REASSEMBLY_STREAMS {
            return Err(VeyronError::Internal(
                "too many concurrent fragment streams".into(),
            ));
        }

        let chunk = frame.payload[FRAG_HEADER_SIZE..].to_vec();
        let entry = self
            .reassembly
            .entry(hdr.stream_id)
            .or_insert_with(|| ReassemblyBuf {
                fragments: HashMap::new(),
                total: hdr.total,
                target: frame.target,
                flags: frame.flags & !(FLAG_FRAGMENTED | FLAG_MAC_PRESENT),
                first_seen: Instant::now(),
                buffered_bytes: 0,
            });
        // A re-sent sequence replaces its old bytes; subtracting first keeps the
        // arithmetic underflow-free (buffered_bytes >= replaced_len always holds),
        // matching the kernel's reassembly accounting in src/ipc/connection.rs.
        let replaced_len = entry.fragments.get(&hdr.sequence).map_or(0, Vec::len);
        let new_total = entry.buffered_bytes - replaced_len + chunk.len();
        if new_total > MAX_PAYLOAD_SIZE {
            self.reassembly.remove(&hdr.stream_id);
            return Err(VeyronError::PayloadTooLarge(MAX_PAYLOAD_SIZE + 1));
        }
        entry.buffered_bytes = new_total;
        entry.fragments.insert(hdr.sequence, chunk);

        if entry.is_complete() {
            let buf = self.reassembly.remove(&hdr.stream_id).unwrap();
            let target = buf.target;
            let flags = buf.flags;
            let payload = buf.reassemble();
            let crc32 = crc32fast::hash(&payload);
            return Ok(Some(Frame {
                magic: 0x5652,
                flags,
                length: payload.len() as u32,
                target,
                crc32,
                payload: payload.into(),
                mac: None,
            }));
        }
        Ok(None)
    }

    // ── Kernel requests ─────────────────────────────────────────────

    /// Subscribe to event types ("*" for all).
    pub async fn subscribe(&mut self, event_types: Vec<String>) -> Result<(), VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::Subscribe(Subscribe { event_types })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Unsubscribe from event types.
    pub async fn unsubscribe(&mut self, event_types: Vec<String>) -> Result<(), VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::Unsubscribe(Unsubscribe { event_types })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Acknowledge a delivered event so the kernel stops retrying it.
    pub async fn ack_event(&mut self, event_id: &str) -> Result<(), VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::EventAck(EventAck {
                event_id: event_id.to_string(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Publish an event to the kernel event bus. The kernel namespaces
    /// `event_type` as `"plugin.<this-client's-registered-id>.<event_type>"`
    /// before delivering it to subscribers.
    /// Requires `PERMISSION_EVENT_PUBLISH`. `timeout_ms == 0` uses the
    /// kernel default of 30s.
    pub async fn publish_event(
        &mut self,
        event_type: &str,
        payload_json: &[u8],
        timeout_ms: u32,
    ) -> Result<EventPublishAck, VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::EventPublish(EventPublish {
                event_type: event_type.to_string(),
                payload_json: payload_json.to_vec(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;

        let timeout = if timeout_ms == 0 {
            DEFAULT_REQUEST_TIMEOUT
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(VeyronError::Timeout);
            }
            let response = self.recv_timeout(remaining).await?;
            match response.payload {
                Some(envelope::Payload::EventPublishAck(ack)) => return Ok(ack),
                Some(envelope::Payload::Error(err)) => {
                    return Err(VeyronError::Internal(format!(
                        "kernel error: {} ({})",
                        err.message, err.details
                    )));
                }
                _ => continue, // unrelated traffic while waiting
            }
        }
    }

    /// Ask the kernel to perform an action (e.g. `"get_weather"`,
    /// `"play_audio"`) and await its [`ActionResponse`]. `timeout_ms == 0`
    /// uses the kernel default of 30 s. Frames that arrive while waiting but
    /// are not the matching response are discarded — drive request/response
    /// traffic from a single task.
    pub async fn send_action(
        &mut self,
        action: &str,
        params_json: &[u8],
        timeout_ms: u32,
    ) -> Result<ActionResponse, VeyronError> {
        let action_id = next_request_id("act");
        let env = Envelope {
            payload: Some(envelope::Payload::ActionRequest(ActionRequest {
                action_id: action_id.clone(),
                action: action.to_string(),
                params_json: params_json.to_vec(),
                timeout_ms,
                streaming: false,
                ..Default::default()
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;

        let timeout = if timeout_ms == 0 {
            DEFAULT_REQUEST_TIMEOUT
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(VeyronError::Timeout);
            }
            let response = self.recv_timeout(remaining).await?;
            match response.payload {
                Some(envelope::Payload::ActionResponse(resp)) if resp.action_id == action_id => {
                    return Ok(resp);
                }
                Some(envelope::Payload::ActionStreamAbort(abort))
                    if abort.action_id == action_id =>
                {
                    return Err(VeyronError::Internal(format!(
                        "stream aborted: {}",
                        abort.reason
                    )));
                }
                Some(envelope::Payload::Error(err)) => {
                    return Err(VeyronError::Internal(format!(
                        "kernel error: {} ({})",
                        err.message, err.details
                    )));
                }
                _ => continue, // unrelated traffic while waiting
            }
        }
    }

    /// Like [`VeyronClient::send_action`] but for an action whose body will
    /// be delivered incrementally via [`VeyronClient::send_request_chunk`]
    /// rather than all at once in `params_json`. Returns the generated
    /// `action_id` immediately — this does NOT wait for an `ActionResponse`;
    /// drive that separately via [`VeyronClient::recv`]/`recv_timeout`,
    /// matching on the same `action_id` (mirrors `send_action`'s own
    /// single-task-drives-request/response convention).
    pub async fn send_action_streaming(
        &mut self,
        action: &str,
        timeout_ms: u32,
    ) -> Result<String, VeyronError> {
        let action_id = next_request_id("act");
        let env = Envelope {
            payload: Some(envelope::Payload::ActionRequest(ActionRequest {
                action_id: action_id.clone(),
                action: action.to_string(),
                params_json: vec![],
                timeout_ms,
                streaming: true,
                ..Default::default()
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        Ok(action_id)
    }

    /// Send one chunk of a streaming action's request body. `action_id` is
    /// the id returned by [`VeyronClient::send_action_streaming`]. Set
    /// `is_final` on the last chunk.
    pub async fn send_request_chunk(
        &mut self,
        action_id: &str,
        seq: u32,
        chunk: Vec<u8>,
        is_final: bool,
    ) -> Result<(), VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::ActionRequestChunk(ActionRequestChunk {
                action_id: action_id.to_string(),
                seq,
                chunk,
                r#final: is_final,
            })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Provider-side: send one chunk of a streaming action's response body.
    /// `action_id` here is the id from the `ActionRequest` the provider
    /// received (already kernel-internal, matching how a provider's terminal
    /// `ActionResponse` is addressed today). Terminate the stream with a
    /// normal `ActionResponse` — there is no separate "final" response chunk.
    pub async fn send_response_chunk(
        &mut self,
        action_id: &str,
        seq: u32,
        chunk: Vec<u8>,
    ) -> Result<(), VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::ActionResponseChunk(
                ActionResponseChunk {
                    action_id: action_id.to_string(),
                    seq,
                    chunk,
                },
            )),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// R6-04: gracefully close a long-lived streaming session. `action_id`
    /// is whichever id this side already uses to address the session — the
    /// original `action_id` on the requester side (same as
    /// [`VeyronClient::send_request_chunk`]), or the kernel-internal id on
    /// the provider side (same as [`VeyronClient::send_response_chunk`]).
    /// The kernel forwards this to the other peer and evicts the session;
    /// only valid after the session has been accepted (the provider's first
    /// `ActionResponse{status: ACTION_OK}`) — closing before that is
    /// rejected as a protocol error.
    pub async fn close_session(
        &mut self,
        action_id: &str,
        reason: &str,
    ) -> Result<(), VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::SessionClose(SessionClose {
                action_id: action_id.to_string(),
                reason: reason.to_string(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await
    }

    /// Send a [`KernelCommand`] and await its ack.
    pub async fn send_command(
        &mut self,
        command_id: &str,
        command: &str,
        params_json: &[u8],
    ) -> Result<KernelCommandAck, VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::KernelCommand(KernelCommand {
                command_id: command_id.to_string(),
                command: command.to_string(),
                params_json: params_json.to_vec(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        let response = self.recv().await?;
        match response.payload {
            Some(envelope::Payload::KernelCommandAck(ack)) => Ok(ack),
            _ => Err(VeyronError::Internal("expected KernelCommandAck".into())),
        }
    }

    /// Round-trip a Ping to the kernel; returns measured latency.
    pub async fn ping(&mut self) -> Result<Duration, VeyronError> {
        let start = Instant::now();
        let env = Envelope {
            payload: Some(envelope::Payload::Ping(Ping {
                timestamp: unix_millis(),
            })),
            ..Default::default()
        };
        self.send("kernel", env).await?;
        let response = self.recv().await?;
        match response.payload {
            Some(envelope::Payload::Pong(_)) => Ok(start.elapsed()),
            _ => Err(VeyronError::Internal("expected Pong".into())),
        }
    }

    // ── Audio ───────────────────────────────────────────────────────

    /// Send an [`AudioStreamChunk`] (stream negotiation / Opus-over-envelope)
    /// to a peer plugin. Requires `PERMISSION_AUDIO_STREAM`.
    pub async fn send_audio_chunk(
        &mut self,
        target: &str,
        chunk: AudioStreamChunk,
    ) -> Result<(), VeyronError> {
        let env = Envelope {
            payload: Some(envelope::Payload::AudioStreamChunk(chunk)),
            ..Default::default()
        };
        self.send(target, env).await
    }

    /// Send raw audio bytes (PCM_S16LE or Opus) with `FLAG_RAW_BINARY`; the
    /// router skips Protobuf decode. Stream metadata must be negotiated first
    /// via [`VeyronClient::send_audio_chunk`]. Requires
    /// `PERMISSION_AUDIO_STREAM`. Raw-binary payloads are never compressed.
    pub async fn send_raw_audio(&mut self, target: &str, data: Vec<u8>) -> Result<(), VeyronError> {
        self.send_raw_with_flags(target, FLAG_RAW_BINARY, data)
            .await
    }
}

fn build_frame(target: &str, flags: u16, payload: Vec<u8>) -> Frame {
    let mut t = [0u8; 32];
    let b = target.as_bytes();
    let n = b.len().min(32);
    t[..n].copy_from_slice(&b[..n]);
    Frame {
        magic: 0x5652,
        flags,
        length: payload.len() as u32,
        target: t,
        crc32: crc32fast::hash(&payload),
        payload: payload.into(),
        mac: None,
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn next_request_id(prefix: &str) -> String {
    let seq = ACTION_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{seq}", unix_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_frame_truncates_long_target() {
        let long = "x".repeat(64);
        let frame = build_frame(&long, 0, vec![1, 2, 3]);
        assert_eq!(frame.target, [b'x'; 32]);
        assert_eq!(frame.length, 3);
        assert_eq!(frame.crc32, crc32fast::hash(&[1, 2, 3]));
    }

    #[test]
    fn request_ids_are_unique() {
        let a = next_request_id("act");
        let b = next_request_id("act");
        assert_ne!(a, b);
    }
}
