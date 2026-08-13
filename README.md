# veyron-sdk

Rust SDK for writing [Veyron](https://github.com/veyron-core/veyron) plugins.

A Veyron plugin is a separate OS process supervised by the Veyron kernel. It
talks to the kernel over a Unix domain socket using the Veyron wire protocol:
44-byte framed messages carrying Protobuf envelopes, with optional zstd
compression, HMAC-SHA256 frame authentication, and fragmentation.

## Quick start

```rust
use veyron_sdk::{Plugin, VeyronClient, VeyronError};
use veyron_sdk::proto::{envelope, ActionResponse, ActionStatus, Envelope, PluginManifest};

struct EchoPlugin;

impl Plugin for EchoPlugin {
    fn id(&self) -> &str {
        "echo"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest::default()
    }

    async fn on_message(&mut self, envelope: Envelope) -> Result<Option<Envelope>, VeyronError> {
        match envelope.payload {
            Some(envelope::Payload::ActionRequest(req)) => Ok(Some(Envelope {
                payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                    action_id: req.action_id,
                    status: ActionStatus::ActionOk as i32,
                    data_json: req.params_json,
                    error: String::new(),
                })),
                ..Default::default()
            })),
            _ => Ok(None),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), VeyronError> {
    EchoPlugin.run().await
}
```

`Plugin::run` connects, registers, and serves until the kernel asks the plugin
to shut down. The SDK answers `Ping` automatically, acknowledges delivered
events after `on_event` succeeds, and exits the loop on `PluginShutdown`.

## Environment

| Variable             | Meaning                                                        |
|----------------------|----------------------------------------------------------------|
| `VEYRON_SOCKET_PATH` | Kernel UDS path. Default: `XDG_RUNTIME_DIR` → `/run/user/<uid>` → `~/.veyron/run` (never shared `/tmp`). |
| `VEYRON_JWT_TOKEN`   | JWT presented at registration (required on secured kernels).   |
| `VEYRON_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags after registration. |

## Protocol coverage

The SDK re-exports the kernel framing layer (`veyron_sdk::framing`), so the
wire format cannot drift between the two sides. All flag bits from
`docs/FRAMING.md` are handled:

| Flag               | Send                                             | Receive                                    |
|--------------------|--------------------------------------------------|--------------------------------------------|
| `FLAG_MAC_PRESENT` | automatic after secured registration             | verified; untagged frames rejected         |
| `FLAG_COMPRESSED`  | automatic for payloads ≥ 64 KiB                  | decompressed + normalized by `read_frame`  |
| `FLAG_FRAGMENTED`  | `VeyronClient::send_fragmented`                  | reassembled by `recv`/`recv_frame` (64 streams, 1 MiB, 30 s bounds) |
| `FLAG_RAW_BINARY`  | `VeyronClient::send_raw_audio`                   | returned raw by `recv_frame`               |

## Versioning & unpublished crates

The SDK tracks the `veyron-wire` protocol: crate `0.1.x` corresponds to wire
`0.2.x` (protocol v1.4 as of SDK `0.1.3`). Before a crates.io release the
`veyron-wire` dependency may point at a version that isn't published yet —
resolve it from git with a `[patch.crates-io]` override in your own
`Cargo.toml` (or in `.cargo/config.toml`, gitignored):

```toml
[patch.crates-io]
veyron-wire = { git = "https://github.com/veyron-core/veyron-wire" }
```

To release the SDK itself (`cargo publish`), crates.io requires registry
dependencies — switch the `veyron-wire` requirement back to a plain version
spec first, then publish `veyron-wire` before `veyron-sdk`.

## Client API

For lower-level control, use `VeyronClient` directly:

```rust,ignore
let mut client = VeyronClient::connect_with_secret(&socket, secret).await?;
let ack = client.register_with_token("weather", manifest, &jwt).await?;

client.subscribe(vec!["alarm.fired".into()]).await?;
let resp = client.send_action("get_weather", br#"{"city":"Berlin"}"#, 5_000).await?;
let ack = client.publish_event("weather.updated", br#"{"city":"Berlin"}"#, 5_000).await?;
let latency = client.ping().await?;

let action_id = client.send_action_streaming("transcribe", 30_000).await?;
client.send_request_chunk(&action_id, 0, b"hi", true).await?;
client.send_response_chunk(&action_id, 0, b"ok").await?;
client.close_session(&action_id, "done").await?;
```

`publish_event` requires `PERMISSION_EVENT_PUBLISH`; `timeout_ms == 0` uses
the kernel's 30s default. It returns the kernel's `EventPublishAck` as-is —
inspect `ack.status` yourself (`EVENT_PUBLISH_OK`/`ERROR`/`PERMISSION_DENY`)
— and only errors on a kernel `Error` envelope or on timeout.

`send_action` follows the same `timeout_ms == 0` → 30s-default convention
and returns the kernel's `ActionResponse` as-is (inspect `.status` yourself).
It errors on a kernel `Error` envelope, on an `ActionStreamAbort` for this
`action_id`, or on timeout. `send_action_streaming` fires an
`ActionRequest{streaming: true}` and returns its generated `action_id`
immediately, without waiting for any response — drive `recv`/chunks yourself
afterward. `send_request_chunk`, `send_response_chunk`, and `close_session`
are fire-and-forget sends (no response awaited); `close_session` has no
`final` flag — the response side of a stream is terminated by an ordinary
`ActionResponse`.

Requests and responses are matched on a single connection; drive
request/response traffic from one task, or use the `Plugin` trait's serve
loop.

## License

MIT
