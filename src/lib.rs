//! # Veyron Rust SDK
//!
//! Write Veyron plugins in Rust. A plugin is a separate OS process that talks
//! to the Veyron kernel over a Unix domain socket using the Veyron wire
//! protocol (length-prefixed frames carrying Protobuf envelopes; see
//! `docs/FRAMING.md` in the Veyron repository).
//!
//! ## Quick start
//!
//! ```no_run
//! use veyron_sdk::{Plugin, VeyronClient};
//! use veyron_sdk::proto::{envelope, ActionResponse, ActionStatus, Envelope, PluginManifest};
//! use veyron_sdk::VeyronError;
//!
//! struct EchoPlugin;
//!
//! impl Plugin for EchoPlugin {
//!     fn id(&self) -> &str {
//!         "echo"
//!     }
//!
//!     fn manifest(&self) -> PluginManifest {
//!         PluginManifest::default()
//!     }
//!
//!     async fn on_message(&mut self, envelope: Envelope) -> Result<Option<Envelope>, VeyronError> {
//!         match envelope.payload {
//!             Some(envelope::Payload::ActionRequest(req)) => Ok(Some(Envelope {
//!                 payload: Some(envelope::Payload::ActionResponse(ActionResponse {
//!                     action_id: req.action_id,
//!                     status: ActionStatus::ActionOk as i32,
//!                     data_json: req.params_json,
//!                     error: String::new(),
//!                 })),
//!                 ..Default::default()
//!             })),
//!             _ => Ok(None),
//!         }
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), VeyronError> {
//!     EchoPlugin.run().await
//! }
//! ```
//!
//! ## Environment
//!
//! | Variable             | Meaning                                                    |
//! |----------------------|------------------------------------------------------------|
//! | `VEYRON_SOCKET_PATH` | Kernel UDS path (default: per-user runtime dir)            |
//! | `VEYRON_JWT_TOKEN`   | JWT presented at registration (secured kernels)            |
//! | `VEYRON_JWT_SECRET`  | Shared secret; enables per-frame HMAC-SHA256 tags          |
//!
//! ## Protocol coverage
//!
//! Compression (`FLAG_COMPRESSED`), frame MACs (`FLAG_MAC_PRESENT`),
//! fragmentation (`FLAG_FRAGMENTED`) and raw audio (`FLAG_RAW_BINARY`) are all
//! handled — see [`VeyronClient`] for the transport API and [`framing`] for
//! the shared wire-format primitives.

pub mod client;
pub mod framing;
pub mod plugin;

pub use client::VeyronClient;
pub use plugin::Plugin;
pub use veyron_wire::WireError as VeyronError;

/// Frame-MAC primitives (HKDF session-key derivation, HMAC-SHA256 tags),
/// shared with the kernel.
pub use veyron_wire::mac as frame_mac;

/// Generated Protobuf types for the Veyron protocol
/// (`wire/proto/veyron_protocol.proto`).
pub mod proto {
    pub use veyron_wire::proto::veyron::*;
}
