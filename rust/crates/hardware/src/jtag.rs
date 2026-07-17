use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JtagInterface {
    pub detected: bool,
    pub protocol: String,
    pub pins: Vec<JtagPin>,
    pub voltage: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JtagPin {
    pub function: String,
    pub pin_number: Option<u8>,
    pub expected_voltage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwdInterface {
    pub detected: bool,
    pub swdio_pin: Option<u8>,
    pub swclk_pin: Option<u8>,
    pub voltage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugInterfaceResult {
    pub jtag: JtagInterface,
    pub swd: SwdInterface,
    pub total_debug_pins: usize,
    pub recommendations: Vec<String>,
}

pub struct JtagDetector;

impl Default for JtagDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl JtagDetector {
    pub fn new() -> Self {
        JtagDetector
    }

    pub fn probe(pin_voltages: &[(u8, f64, &str)]) -> DebugInterfaceResult {
        let mut jtag = JtagInterface {
            detected: false,
            protocol: "JTAG".to_string(),
            pins: Vec::new(),
            voltage: 0.0,
            confidence: 0.0,
        };

        let mut swd = SwdInterface {
            detected: false,
            swdio_pin: None,
            swclk_pin: None,
            voltage: 0.0,
        };

        let mut tck_candidates = Vec::new();
        let mut tms_candidates = Vec::new();
        let mut tdi_candidates = Vec::new();
        let mut tdo_candidates = Vec::new();
        let mut swdio_candidates = Vec::new();
        let mut swclk_candidates = Vec::new();
        let mut debug_pins = 0usize;

        for (pin, voltage, label) in pin_voltages {
            let lower = label.to_lowercase();
            if lower.contains("tck") || lower.contains("jtag_clk") {
                tck_candidates.push(*pin);
                jtag.pins.push(JtagPin {
                    function: "TCK".to_string(),
                    pin_number: Some(*pin),
                    expected_voltage: *voltage,
                });
                debug_pins += 1;
            } else if lower.contains("tms") {
                tms_candidates.push(*pin);
                jtag.pins.push(JtagPin {
                    function: "TMS".to_string(),
                    pin_number: Some(*pin),
                    expected_voltage: *voltage,
                });
                debug_pins += 1;
            } else if lower.contains("tdi") {
                tdi_candidates.push(*pin);
                jtag.pins.push(JtagPin {
                    function: "TDI".to_string(),
                    pin_number: Some(*pin),
                    expected_voltage: *voltage,
                });
                debug_pins += 1;
            } else if lower.contains("tdo") {
                tdo_candidates.push(*pin);
                jtag.pins.push(JtagPin {
                    function: "TDO".to_string(),
                    pin_number: Some(*pin),
                    expected_voltage: *voltage,
                });
                debug_pins += 1;
            } else if lower.contains("swdio") || lower.contains("swio") {
                swdio_candidates.push(*pin);
                swd.swdio_pin = Some(*pin);
                debug_pins += 1;
            } else if lower.contains("swclk") || lower.contains("swc") {
                swclk_candidates.push(*pin);
                swd.swclk_pin = Some(*pin);
                debug_pins += 1;
            }
        }

        let jtag_pins = tck_candidates.len() + tms_candidates.len() + tdi_candidates.len() + tdo_candidates.len();
        if jtag_pins >= 4 {
            jtag.detected = true;
            jtag.confidence = 0.9;
            jtag.voltage = pin_voltages.iter().find(|(p, _, _)| tck_candidates.contains(p))
                .map(|(_, v, _)| *v).unwrap_or(3.3);
        } else if jtag_pins >= 2 {
            jtag.detected = true;
            jtag.confidence = 0.5;
        }

        if swd.swdio_pin.is_some() || swd.swclk_pin.is_some() {
            swd.detected = true;
        }

        let recommendations = Self::generate_recommendations(&jtag, &swd);

        DebugInterfaceResult {
            jtag,
            swd,
            total_debug_pins: debug_pins,
            recommendations,
        }
    }

    fn generate_recommendations(jtag: &JtagInterface, swd: &SwdInterface) -> Vec<String> {
        let mut recs = Vec::new();

        if jtag.detected && jtag.confidence > 0.7 {
            recs.push(format!(
                "JTAG interface detected on pins: {}",
                jtag.pins.iter()
                    .filter_map(|p| p.pin_number.map(|n| format!("P{}={}", n, p.function)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            recs.push("JTAG can be used for: firmware dumping, debugging, flashing".to_string());
        }

        if swd.detected {
            recs.push(format!(
                "SWD interface detected (SWDIO: {:?}, SWCLK: {:?})",
                swd.swdio_pin, swd.swclk_pin
            ));
            recs.push("SWD can be used with: Black Magic Probe, J-Link, ST-Link".to_string());
        }

        if !jtag.detected && !swd.detected {
            recs.push("No debug interface detected. Check pin labels or voltages.".to_string());
        }

        recs
    }

    pub fn common_jtag_pinouts() -> Vec<(&'static str, Vec<(&'static str, u8)>)> {
        vec![
            ("ARM 20-pin (standard)", vec![
                ("VTREF", 1), ("GND", 3), ("TMS", 5), ("TCK", 7),
                ("TDO", 9), ("TDI", 11), ("nSRST", 13), ("GND", 15),
                ("GND", 17), ("GND", 19),
            ]),
            ("ARM Cortex 10-pin", vec![
                ("VTREF", 1), ("SWDIO", 3), ("GND", 5), ("SWCLK", 7),
                ("GND", 9),
            ]),
            ("TI 14-pin", vec![
                ("TMS", 1), ("TCK", 3), ("TDO", 5), ("TDI", 7),
                ("nTRST", 11), ("EMU0", 13), ("EMU1", 14),
            ]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_jtag() {
        let pins = vec![
            (1, 3.3, "VTREF"),
            (5, 3.3, "TMS"),
            (7, 3.3, "TCK"),
            (9, 3.3, "TDO"),
            (11, 3.3, "TDI"),
        ];
        let result = JtagDetector::probe(&pins);
        assert!(result.jtag.detected);
        assert!(result.jtag.confidence > 0.7);
    }

    #[test]
    fn test_probe_swd() {
        let pins = vec![
            (1, 3.3, "VTREF"),
            (3, 3.3, "SWDIO"),
            (7, 3.3, "SWCLK"),
        ];
        let result = JtagDetector::probe(&pins);
        assert!(result.swd.detected);
    }

    #[test]
    fn test_probe_none() {
        let result = JtagDetector::probe(&[]);
        assert!(!result.jtag.detected);
    }

    #[test]
    fn test_common_jtag_pinouts() {
        let pinouts = JtagDetector::common_jtag_pinouts();
        assert!(pinouts.iter().any(|(name, _)| name.contains("ARM")));
    }

    #[test]
    fn test_probe_partial_jtag() {
        let pins = vec![
            (5, 3.3, "TMS"),
            (7, 3.3, "TCK"),
        ];
        let result = JtagDetector::probe(&pins);
        assert!(result.jtag.detected);
        assert!(result.jtag.confidence < 0.7);
    }

    #[test]
    fn test_debug_interface_serde() {
        let jtag = JtagInterface {
            detected: true,
            protocol: "JTAG".to_string(),
            pins: vec![JtagPin { function: "TCK".to_string(), pin_number: Some(7), expected_voltage: 3.3 }],
            voltage: 3.3,
            confidence: 0.9,
        };
        let json = serde_json::to_string_pretty(&jtag).unwrap();
        assert!(json.contains("TCK"));
    }
}
