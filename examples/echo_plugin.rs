//! Lightweight demo plugin for the Vynkor Rust SDK.
//!
//! Shows: manifest declaration, event subscription in `on_init`, action
//! handling in `on_message`, and event delivery via `on_event`.
//!
//! Run (with a kernel listening on the default socket):
//!     VYN_JWT_TOKEN=<token> cargo run -p vynkor-sdk --example echo_plugin

use vynkor_sdk::proto::{envelope, ActionResponse, ActionStatus, Envelope, Event, PluginManifest};
use vynkor_sdk::{Plugin, VynkorClient, VynkorError};

struct EchoPlugin;

impl Plugin for EchoPlugin {
    fn id(&self) -> &str {
        "echo-plugin"
    }

    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            actions: vec!["echo".into()],
            events: vec!["system.low_memory".into()],
            ..Default::default()
        }
    }

    async fn on_init(&mut self, client: &mut VynkorClient) -> Result<(), VynkorError> {
        println!("[{}] registered, subscribing to events", self.id());
        client.subscribe(self.manifest().events).await
    }

    async fn on_message(&mut self, envelope: Envelope) -> Result<Option<Envelope>, VynkorError> {
        match envelope.payload {
            Some(envelope::Payload::ActionRequest(req)) if req.action == "echo" => {
                Ok(Some(Envelope {
                    payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                        action_id: req.action_id,
                        status: ActionStatus::ActionOk as i32,
                        data_json: req.params_json,
                        error: String::new(),
                    })),
                    ..Default::default()
                }))
            }
            Some(envelope::Payload::ActionRequest(req)) => Ok(Some(Envelope {
                payload: Some(envelope::Payload::ActionResponse(ActionResponse {
                    action_id: req.action_id,
                    status: ActionStatus::ActionNotFound as i32,
                    data_json: Vec::new(),
                    error: format!("unknown action: {}", req.action),
                })),
                ..Default::default()
            })),
            other => {
                println!("[{}] unhandled message: {other:?}", self.id());
                Ok(None)
            }
        }
    }

    async fn on_event(&mut self, event: Event) -> Result<Option<Envelope>, VynkorError> {
        println!(
            "[{}] event {}: {:?}",
            self.id(),
            event.event_type,
            event.payload_json
        );
        Ok(None)
    }

    async fn on_shutdown(&mut self) -> Result<(), VynkorError> {
        println!("[{}] shutting down", self.id());
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), VynkorError> {
    EchoPlugin.run().await
}
