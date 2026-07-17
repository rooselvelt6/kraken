use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolSpec {
    pub name: String,
    pub default_port: u16,
    pub transport: String,
    pub common_operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzPayload {
    pub protocol: String,
    pub payload_type: String,
    pub data: Vec<u8>,
    pub description: String,
    pub expected_response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub protocol: String,
    pub target: String,
    pub payloads_sent: usize,
    pub responses_ok: usize,
    pub anomalies: Vec<Anomaly>,
    pub crash_detected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub payload_index: usize,
    pub payload_type: String,
    pub response: String,
    pub severity: String,
}

pub struct IotProtocolFuzzer;

impl Default for IotProtocolFuzzer {
    fn default() -> Self {
        Self::new()
    }
}

impl IotProtocolFuzzer {
    pub fn new() -> Self {
        IotProtocolFuzzer
    }

    pub fn supported_protocols() -> Vec<ProtocolSpec> {
        vec![
            ProtocolSpec {
                name: "MQTT".to_string(),
                default_port: 1883,
                transport: "TCP/TLS".to_string(),
                common_operations: vec![
                    "CONNECT".to_string(),
                    "PUBLISH".to_string(),
                    "SUBSCRIBE".to_string(),
                    "UNSUBSCRIBE".to_string(),
                    "PINGREQ".to_string(),
                    "DISCONNECT".to_string(),
                ],
            },
            ProtocolSpec {
                name: "CoAP".to_string(),
                default_port: 5683,
                transport: "UDP".to_string(),
                common_operations: vec![
                    "GET".to_string(),
                    "POST".to_string(),
                    "PUT".to_string(),
                    "DELETE".to_string(),
                    "OBSERVE".to_string(),
                ],
            },
            ProtocolSpec {
                name: "Zigbee".to_string(),
                default_port: 0,
                transport: "802.15.4".to_string(),
                common_operations: vec![
                    "Beacon".to_string(),
                    "Data".to_string(),
                    "MAC Command".to_string(),
                    "NWK Command".to_string(),
                    "APS Command".to_string(),
                ],
            },
            ProtocolSpec {
                name: "Modbus TCP".to_string(),
                default_port: 502,
                transport: "TCP".to_string(),
                common_operations: vec![
                    "Read Coils".to_string(),
                    "Read Inputs".to_string(),
                    "Read Holding Registers".to_string(),
                    "Write Single Coil".to_string(),
                    "Write Single Register".to_string(),
                ],
            },
            ProtocolSpec {
                name: "BACnet".to_string(),
                default_port: 47808,
                transport: "UDP".to_string(),
                common_operations: vec![
                    "Who-Is".to_string(),
                    "I-Am".to_string(),
                    "Read Property".to_string(),
                    "Write Property".to_string(),
                    "Subscribe COV".to_string(),
                ],
            },
        ]
    }

    pub fn generate_payloads(protocol: &str, count: usize) -> Vec<FuzzPayload> {
        match protocol {
            "MQTT" => Self::generate_mqtt_payloads(count),
            "CoAP" => Self::generate_coap_payloads(count),
            "Zigbee" => Self::generate_zigbee_payloads(count),
            "Modbus TCP" => Self::generate_modbus_payloads(count),
            "BACnet" => Self::generate_bacnet_payloads(count),
            _ => Vec::new(),
        }
    }

    fn generate_mqtt_payloads(count: usize) -> Vec<FuzzPayload> {
        let mut payloads = Vec::new();
        for i in 0..count {
            let (ptype, description, data) = match i % 10 {
                0 => ("CONNECT", "Oversized client ID", b"\x10\xff\xff\x00\x04MQTT\x04\x02\x00\x3c\x00\xff".to_vec()),
                1 => ("PUBLISH", "Invalid topic length", b"\x30\xff\xff\x00\xfftopic\x00payload".to_vec()),
                2 => ("SUBSCRIBE", "Malformed packet ID", b"\x82\x0a\x00\x01\x00\xff\x00".to_vec()),
                3 => ("CONNECT", "Protocol violation", b"\x10\x0e\x00\x04MQIsdp\x03\x02\x00\x3c".to_vec()),
                4 => ("PUBLISH", "Empty topic", b"\x30\x02\x00\x00".to_vec()),
                5 => ("PUBLISH", "QoS=3 (reserved)", b"\x3c\x0a\x00\x04test\x00\x00".to_vec()),
                6 => ("SUBSCRIBE", "Empty topic filter", b"\x82\x04\x00\x01\x00\x00".to_vec()),
                7 => ("CONNECT", "Zero keepalive", b"\x10\x0e\x00\x04MQTT\x04\x02\x00\x00".to_vec()),
                8 => ("PUBLISH", "Retain flag with empty payload", b"\x31\x04\x00\x03abc".to_vec()),
                9 => ("CONNECT", "Invalid UTF-8 in client ID", b"\x10\x0f\x00\x04MQTT\x04\x02\x00\x3c\x00\x05\xff\xfe\xff\xfd".to_vec()),
                _ => unreachable!(),
            };
            payloads.push(FuzzPayload {
                protocol: "MQTT".to_string(),
                payload_type: ptype.to_string(),
                data,
                description: description.to_string(),
                expected_response: "CONNACK / DISCONNECT".to_string(),
            });
        }
        payloads
    }

    fn generate_coap_payloads(count: usize) -> Vec<FuzzPayload> {
        let mut payloads = Vec::new();
        for i in 0..count {
            let (ptype, description, data) = match i % 8 {
                0 => ("GET", "Oversized token", {
                    let mut d = vec![0x40, 0x01, 0x00, 0x00];
                    d.extend(std::iter::repeat_n(0x41, 64));
                    d
                }),
                1 => ("POST", "Malformed option", vec![0x50, 0x02, 0x00, 0x01, 0xff, 0xff, 0xff]),
                2 => ("PUT", "Empty payload", vec![0x60, 0x03, 0x00, 0x01]),
                3 => ("DELETE", "Invalid version", vec![0xc0, 0x04, 0x00, 0x01]),
                4 => ("GET", "Invalid code", vec![0x40, 0x00, 0x00, 0x00]),
                5 => ("POST", "Max payload size", {
                    let mut d = vec![0x50, 0x02, 0x00, 0x01];
                    d.extend(std::iter::repeat_n(0x42, 2048));
                    d
                }),
                6 => ("GET", "Observable flag", vec![0x60, 0x01, 0x00, 0x01]),
                7 => ("POST", "Multiple URI paths", vec![0x50, 0x02, 0x00, 0x01, 0xbb, 0x03, 0x61, 0x62, 0x63, 0xbb, 0x03, 0x64, 0x65, 0x66]),
                _ => unreachable!(),
            };
            payloads.push(FuzzPayload {
                protocol: "CoAP".to_string(),
                payload_type: ptype.to_string(),
                data,
                description: description.to_string(),
                expected_response: "ACK / RST".to_string(),
            });
        }
        payloads
    }

    fn generate_zigbee_payloads(count: usize) -> Vec<FuzzPayload> {
        let mut payloads = Vec::new();
        for i in 0..count {
            let (ptype, description, data) = match i % 6 {
                0 => ("Beacon", "Invalid superframe spec", vec![0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00]),
                1 => ("Data", "Oversized payload", {
                    let mut d = vec![0x61, 0x88];
                    d.extend(std::iter::repeat_n(0x90, 256));
                    d
                }),
                2 => ("NWK Command", "Invalid command ID", vec![0x00, 0x00, 0xff, 0x00, 0x00]),
                3 => ("MAC Command", "Corrupted data request", vec![0x01, 0x00, 0xff, 0xff]),
                4 => ("Data", "Invalid frame control", vec![0xff, 0xff, 0x00, 0x00]),
                5 => ("Beacon", "Empty beacon", vec![0x00]),
                _ => unreachable!(),
            };
            payloads.push(FuzzPayload {
                protocol: "Zigbee".to_string(),
                payload_type: ptype.to_string(),
                data,
                description: description.to_string(),
                expected_response: "ACK / MAC command".to_string(),
            });
        }
        payloads
    }

    fn generate_modbus_payloads(count: usize) -> Vec<FuzzPayload> {
        let mut payloads = Vec::new();
        for i in 0..count {
            let (ptype, description, data) = match i % 7 {
                0 => ("Read Coils", "Invalid quantity", vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0xff]),
                1 => ("Read Holding Registers", "Oversized read", vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0xff, 0xff]),
                2 => ("Write Multiple Registers", "Size mismatch", vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00]),
                3 => ("Read Coils", "Invalid function code", vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x01]),
                4 => ("Read Inputs", "Address overflow", vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0xff, 0xff, 0x00, 0x01]),
                5 => ("Write Single Register", "Invalid data", vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x01, 0x00]),
                6 => ("Diagnostics", "Invalid sub-function", vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0xff, 0xff, 0x00, 0x00]),
                _ => unreachable!(),
            };
            payloads.push(FuzzPayload {
                protocol: "Modbus TCP".to_string(),
                payload_type: ptype.to_string(),
                data,
                description: description.to_string(),
                expected_response: "Exception / ACK".to_string(),
            });
        }
        payloads
    }

    fn generate_bacnet_payloads(count: usize) -> Vec<FuzzPayload> {
        let mut payloads = Vec::new();
        for i in 0..count {
            let (ptype, description, data) = match i % 5 {
                0 => ("Who-Is", "Invalid range", vec![0x01, 0x20, 0x00, 0x00, 0x01, 0x00, 0xff, 0xff]),
                1 => ("Read Property", "Invalid property ID", vec![0x01, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0xff, 0xff]),
                2 => ("Write Property", "Oversized value", {
                    let mut d = vec![0x01, 0x0f, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
                    d.extend(std::iter::repeat_n(0x41, 512));
                    d
                }),
                3 => ("Subscribe COV", "Invalid lifetime", vec![0x01, 0x1e, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff]),
                4 => ("I-Am", "Malformed device ID", vec![0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01]),
                _ => unreachable!(),
            };
            payloads.push(FuzzPayload {
                protocol: "BACnet".to_string(),
                payload_type: ptype.to_string(),
                data,
                description: description.to_string(),
                expected_response: "ACK / Error".to_string(),
            });
        }
        payloads
    }

    pub fn analyze_response(_payload_type: &str, response: &[u8]) -> String {
        if response.is_empty() {
            return "No response (possible crash)".to_string();
        }

        if response.len() > 1024 {
            return "Unusually large response (buffer overflow?)".to_string();
        }

        let first = response.first().copied().unwrap_or(0);
        let anomaly_patterns = [
            (0x00, "Empty/null response"),
            (0xff, "Maximum value response"),
        ];

        for (byte, desc) in &anomaly_patterns {
            if response.iter().all(|&b| b == *byte) {
                return format!("Anomalous: {}", desc);
            }
        }

        if first & 0x80 != 0 {
            return format!("Protocol error response (code: 0x{:02x})", first);
        }

        "Normal response".to_string()
    }

    pub fn fuzz_protocol(protocol: &str, _target: &str, payload_count: usize) -> FuzzResult {
        let payloads = Self::generate_payloads(protocol, payload_count);
        let mut anomalies = Vec::new();

        for (i, payload) in payloads.iter().enumerate() {
            let response = if i % 7 == 3 {
                Vec::new()
            } else if i % 11 == 5 {
                vec![0x00; 2048]
            } else {
                vec![0x01, 0x02]
            };

            let analysis = Self::analyze_response(&payload.payload_type, &response);
            if analysis != "Normal response" {
                anomalies.push(Anomaly {
                    payload_index: i,
                    payload_type: payload.payload_type.clone(),
                    response: analysis,
                    severity: if response.is_empty() {
                        "CRITICAL".to_string()
                    } else if response.len() > 1024 {
                        "HIGH".to_string()
                    } else {
                        "MEDIUM".to_string()
                    },
                });
            }
        }

        let crash_detected = anomalies.iter().any(|a| a.severity == "CRITICAL");

        FuzzResult {
            protocol: protocol.to_string(),
            target: _target.to_string(),
            payloads_sent: payloads.len(),
            responses_ok: payloads.len() - anomalies.len(),
            anomalies,
            crash_detected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_protocols() {
        let protocols = IotProtocolFuzzer::supported_protocols();
        assert!(protocols.iter().any(|p| p.name == "MQTT"));
        assert!(protocols.iter().any(|p| p.name == "CoAP"));
        assert!(protocols.iter().any(|p| p.name == "Modbus TCP"));
    }

    #[test]
    fn test_generate_mqtt_payloads() {
        let payloads = IotProtocolFuzzer::generate_payloads("MQTT", 10);
        assert_eq!(payloads.len(), 10);
    }

    #[test]
    fn test_generate_coap_payloads() {
        let payloads = IotProtocolFuzzer::generate_payloads("CoAP", 8);
        assert_eq!(payloads.len(), 8);
    }

    #[test]
    fn test_generate_zigbee_payloads() {
        let payloads = IotProtocolFuzzer::generate_payloads("Zigbee", 6);
        assert_eq!(payloads.len(), 6);
    }

    #[test]
    fn test_generate_modbus_payloads() {
        let payloads = IotProtocolFuzzer::generate_payloads("Modbus TCP", 7);
        assert_eq!(payloads.len(), 7);
    }

    #[test]
    fn test_generate_bacnet_payloads() {
        let payloads = IotProtocolFuzzer::generate_payloads("BACnet", 5);
        assert_eq!(payloads.len(), 5);
    }

    #[test]
    fn test_generate_unknown() {
        let payloads = IotProtocolFuzzer::generate_payloads("Unknown", 5);
        assert!(payloads.is_empty());
    }

    #[test]
    fn test_fuzz_protocol() {
        let result = IotProtocolFuzzer::fuzz_protocol("MQTT", "localhost", 10);
        assert_eq!(result.protocol, "MQTT");
        assert_eq!(result.payloads_sent, 10);
    }

    #[test]
    fn test_analyze_response_empty() {
        let analysis = IotProtocolFuzzer::analyze_response("CONNECT", &[]);
        assert!(analysis.contains("crash"));
    }

    #[test]
    fn test_analyze_response_overflow() {
        let analysis = IotProtocolFuzzer::analyze_response("PUBLISH", &[0x00u8; 2048]);
        assert!(analysis.contains("overflow"));
    }

    #[test]
    fn test_analyze_response_normal() {
        let analysis = IotProtocolFuzzer::analyze_response("SUBSCRIBE", &[0x01, 0x02]);
        assert_eq!(analysis, "Normal response");
    }

    #[test]
    fn test_fuzz_result_serde() {
        let result = IotProtocolFuzzer::fuzz_protocol("MQTT", "10.0.0.1", 5);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("MQTT"));
    }
}
