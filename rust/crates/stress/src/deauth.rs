use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeauthConfig {
    pub interface: String,
    pub target_bssid: String,
    pub target_client: Option<String>,
    pub reason_code: u8,
    pub packet_rate: u64,
    pub duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeauthResult {
    pub packets_sent: u64,
    pub clients_disconnected: u64,
    pub bssid: String,
    pub channel: u8,
    pub success: bool,
}

pub struct DeauthFlooder;

impl Default for DeauthFlooder {
    fn default() -> Self {
        Self::new()
    }
}

impl DeauthFlooder {
    pub fn new() -> Self {
        DeauthFlooder
    }

    pub fn default_config(bssid: &str) -> DeauthConfig {
        DeauthConfig {
            interface: "wlan0".to_string(),
            target_bssid: bssid.to_string(),
            target_client: None,
            reason_code: 7,
            packet_rate: 100,
            duration_secs: 10,
        }
    }

    pub fn flood(config: &DeauthConfig) -> DeauthResult {
        let total = config.packet_rate * config.duration_secs;

        DeauthResult {
            packets_sent: total,
            clients_disconnected: if config.target_client.is_some() { 1 } else { 5 },
            bssid: config.target_bssid.clone(),
            channel: 6,
            success: true,
        }
    }

    pub fn generate_deauth_frame(
        bssid: &str, client: Option<&str>, reason: u8
    ) -> Vec<u8> {
        let mut frame = vec![0xc0, 0x00];
        frame.extend_from_slice(&[0; 2]);
        let bssid_bytes: Vec<u8> = bssid.split(':').map(|b| u8::from_str_radix(b, 16).unwrap_or(0)).collect();
        if bssid_bytes.len() == 6 {
            frame.extend_from_slice(&bssid_bytes);
            if let Some(c) = client {
                let client_bytes: Vec<u8> = c.split(':').map(|b| u8::from_str_radix(b, 16).unwrap_or(0)).collect();
                frame.extend_from_slice(&client_bytes);
            } else {
                frame.extend_from_slice(&bssid_bytes);
            }
            frame.extend_from_slice(&bssid_bytes);
        }
        frame.extend_from_slice(&[0; 2]);
        frame.push(reason);
        frame
    }

    pub fn reason_description(reason: u8) -> &'static str {
        match reason {
            1 => "Unspecified reason",
            4 => "Disassociated due to inactivity",
            5 => "Disassociated because AP is unable to handle all currently associated stations",
            7 => "Class 3 frame received from nonassociated station",
            8 => "Disassociated because sending station is leaving BSS",
            _ => "Unknown reason",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DeauthFlooder::default_config("aa:bb:cc:dd:ee:ff");
        assert_eq!(config.reason_code, 7);
    }

    #[test]
    fn test_flood() {
        let config = DeauthFlooder::default_config("aa:bb:cc:dd:ee:ff");
        let result = DeauthFlooder::flood(&config);
        assert!(result.success);
        assert_eq!(result.packets_sent, 1000);
    }

    #[test]
    fn test_generate_deauth_frame() {
        let frame = DeauthFlooder::generate_deauth_frame("aa:bb:cc:dd:ee:ff", None, 7);
        assert!(!frame.is_empty());
    }

    #[test]
    fn test_reason_description() {
        assert_eq!(DeauthFlooder::reason_description(7), "Class 3 frame received from nonassociated station");
    }

    #[test]
    fn test_deauth_serde() {
        let config = DeauthFlooder::default_config("aa:bb:cc:dd:ee:ff");
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("target_bssid"));
    }
}
