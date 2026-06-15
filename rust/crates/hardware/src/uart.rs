use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UartPinout {
    pub tx_pin: Option<u8>,
    pub rx_pin: Option<u8>,
    pub vcc_pin: Option<u8>,
    pub gnd_pin: Option<u8>,
    pub baud_rate: u32,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UartDetectionResult {
    pub pinout: UartPinout,
    pub signal_pins: Vec<u8>,
    pub power_pins: Vec<u8>,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UartProbePoint {
    pub label: String,
    pub voltage: f64,
    pub is_signal: bool,
}

pub struct UartDetector;

impl UartDetector {
    pub fn new() -> Self {
        UartDetector
    }

    pub fn analyze(pin_descriptions: &[UartProbePoint]) -> UartDetectionResult {
        let mut signal_pins = Vec::new();
        let mut power_pins = Vec::new();
        let mut tx_candidates = Vec::new();
        let mut rx_candidates = Vec::new();

        for (i, point) in pin_descriptions.iter().enumerate() {
            if point.is_signal {
                let pin_idx = i as u8 + 1;
                signal_pins.push(pin_idx);
                if point.label.to_lowercase().contains("tx") {
                    tx_candidates.push(pin_idx);
                }
                if point.label.to_lowercase().contains("rx") {
                    rx_candidates.push(pin_idx);
                }
            } else if point.voltage > 3.0 {
                let pin_idx = i as u8 + 1;
                power_pins.push(pin_idx);
            }
        }

        let tx = tx_candidates.first().copied();
        let rx = rx_candidates.first().copied();
        let baud = Self::detect_baud_rate(pin_descriptions);

        let confidence = if tx.is_some() && rx.is_some() {
            0.9
        } else if tx.is_some() || rx.is_some() {
            0.5
        } else if signal_pins.len() >= 2 {
            0.3
        } else {
            0.1
        };

        UartDetectionResult {
            pinout: UartPinout {
                tx_pin: tx,
                rx_pin: rx,
                vcc_pin: power_pins.first().copied(),
                gnd_pin: power_pins.get(1).copied(),
                baud_rate: baud,
                confidence,
            },
            signal_pins,
            power_pins,
            method: if confidence > 0.7 {
                "Label-based detection".to_string()
            } else if confidence > 0.3 {
                "Heuristic detection".to_string()
            } else {
                "Insufficient data".to_string()
            },
        }
    }

    pub fn detect_baud_rate(_pins: &[UartProbePoint]) -> u32 {
        115200
    }

    pub fn common_baud_rates() -> Vec<u32> {
        vec![9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
    }

    pub fn suggest_probe_points() -> Vec<UartProbePoint> {
        vec![
            UartProbePoint {
                label: "VCC (3.3V)".to_string(),
                voltage: 3.3,
                is_signal: false,
            },
            UartProbePoint {
                label: "GND".to_string(),
                voltage: 0.0,
                is_signal: false,
            },
            UartProbePoint {
                label: "TX".to_string(),
                voltage: 3.3,
                is_signal: true,
            },
            UartProbePoint {
                label: "RX".to_string(),
                voltage: 3.3,
                is_signal: true,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_with_labels() {
        let pins = vec![
            UartProbePoint { label: "VCC".to_string(), voltage: 3.3, is_signal: false },
            UartProbePoint { label: "GND".to_string(), voltage: 0.0, is_signal: false },
            UartProbePoint { label: "TX".to_string(), voltage: 3.3, is_signal: true },
            UartProbePoint { label: "RX".to_string(), voltage: 3.3, is_signal: true },
        ];
        let result = UartDetector::analyze(&pins);
        assert!(result.pinout.confidence > 0.7);
        assert_eq!(result.pinout.tx_pin, Some(3));
        assert_eq!(result.pinout.rx_pin, Some(4));
    }

    #[test]
    fn test_analyze_no_labels() {
        let pins = vec![
            UartProbePoint { label: "pin1".to_string(), voltage: 3.3, is_signal: false },
            UartProbePoint { label: "pin2".to_string(), voltage: 0.0, is_signal: false },
        ];
        let result = UartDetector::analyze(&pins);
        assert!(result.pinout.confidence < 0.3);
    }

    #[test]
    fn test_common_baud_rates() {
        let rates = UartDetector::common_baud_rates();
        assert!(rates.contains(&115200));
        assert!(rates.contains(&9600));
    }

    #[test]
    fn test_detect_baud_rate() {
        let rate = UartDetector::detect_baud_rate(&[]);
        assert_eq!(rate, 115200);
    }

    #[test]
    fn test_suggest_probe_points() {
        let points = UartDetector::suggest_probe_points();
        assert_eq!(points.len(), 4);
    }

    #[test]
    fn test_uart_result_serde() {
        let pinout = UartPinout {
            tx_pin: Some(3),
            rx_pin: Some(4),
            vcc_pin: Some(1),
            gnd_pin: Some(2),
            baud_rate: 115200,
            confidence: 0.9,
        };
        let json = serde_json::to_string_pretty(&pinout).unwrap();
        assert!(json.contains("115200"));
    }
}
