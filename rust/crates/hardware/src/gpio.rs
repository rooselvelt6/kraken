use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum GpioDirection {
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum GpioValue {
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpioPin {
    pub number: u8,
    pub name: String,
    pub direction: GpioDirection,
    pub value: GpioValue,
    pub alt_function: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpioState {
    pub pins: Vec<GpioPin>,
    pub chip_model: String,
    pub pin_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpioConfig {
    pub chip: String,
    pub alt_function_map: Vec<AltFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AltFunction {
    pub pin: u8,
    pub function: String,
}

pub struct GpioController;

impl GpioController {
    pub fn new() -> Self {
        GpioController
    }

    pub fn get_state(pin_count: u8, chip_model: &str) -> GpioState {
        let pins = (0..pin_count).map(|i| {
            let name = Self::default_pin_name(i, chip_model);
            let alt = Self::default_alt_function(i, chip_model);
            GpioPin {
                number: i,
                name,
                direction: GpioDirection::Input,
                value: GpioValue::Low,
                alt_function: alt,
            }
        }).collect();

        GpioState {
            pins,
            chip_model: chip_model.to_string(),
            pin_count,
        }
    }

    fn default_pin_name(pin: u8, _chip: &str) -> String {
        format!("GPIO{}", pin)
    }

    fn default_alt_function(pin: u8, _chip: &str) -> Option<String> {
        match pin {
            2 | 3 => Some("I2C (SDA/SCL)".to_string()),
            14 | 15 => Some("UART (TX/RX)".to_string()),
            9 | 10 | 11 | 8 | 7 => Some("SPI".to_string()),
            12 | 13 => Some("PWM".to_string()),
            _ => None,
        }
    }

    pub fn rpi_gpio_layout() -> GpioConfig {
        GpioConfig {
            chip: "BCM2835".to_string(),
            alt_function_map: vec![
                AltFunction { pin: 2, function: "I2C1 SDA".to_string() },
                AltFunction { pin: 3, function: "I2C1 SCL".to_string() },
                AltFunction { pin: 14, function: "UART0 TX".to_string() },
                AltFunction { pin: 15, function: "UART0 RX".to_string() },
                AltFunction { pin: 18, function: "PWM0".to_string() },
                AltFunction { pin: 19, function: "PWM1".to_string() },
                AltFunction { pin: 9, function: "SPI0 MISO".to_string() },
                AltFunction { pin: 10, function: "SPI0 MOSI".to_string() },
                AltFunction { pin: 11, function: "SPI0 SCLK".to_string() },
                AltFunction { pin: 8, function: "SPI0 CS0".to_string() },
                AltFunction { pin: 7, function: "SPI0 CS1".to_string() },
            ],
        }
    }

    pub fn beaglebone_gpio_layout() -> GpioConfig {
        GpioConfig {
            chip: "AM3358".to_string(),
            alt_function_map: vec![
                AltFunction { pin: 38, function: "UART4 TX".to_string() },
                AltFunction { pin: 39, function: "UART4 RX".to_string() },
                AltFunction { pin: 44, function: "SPI0 CS0".to_string() },
                AltFunction { pin: 45, function: "SPI0 D1".to_string() },
                AltFunction { pin: 46, function: "SPI0 D0".to_string() },
                AltFunction { pin: 47, function: "SPI0 SCLK".to_string() },
                AltFunction { pin: 86, function: "I2C2 SDA".to_string() },
                AltFunction { pin: 87, function: "I2C2 SCL".to_string() },
            ],
        }
    }

    pub fn identify_board(pin_voltages: &[(u8, f64)]) -> String {
        let voltage_3v3 = pin_voltages.iter().filter(|(_, v)| (*v - 3.3).abs() < 0.3).count();
        let voltage_5v = pin_voltages.iter().filter(|(_, v)| (*v - 5.0).abs() < 0.5).count();
        let voltage_1v8 = pin_voltages.iter().filter(|(_, v)| (*v - 1.8).abs() < 0.2).count();

        if voltage_3v3 >= 6 {
            "Raspberry Pi (3.3V logic)".to_string()
        } else if voltage_5v >= 4 && voltage_1v8 >= 2 {
            "BeagleBone (3.3V logic)".to_string()
        } else if voltage_1v8 >= 4 {
            "FPGA / SoC (1.8V logic)".to_string()
        } else if voltage_5v >= 2 {
            "Arduino (5V logic)".to_string()
        } else {
            "Unknown board".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_state() {
        let state = GpioController::get_state(40, "BCM2835");
        assert_eq!(state.pin_count, 40);
        assert_eq!(state.pins.len(), 40);
    }

    #[test]
    fn test_rpi_gpio_layout() {
        let config = GpioController::rpi_gpio_layout();
        assert!(config.alt_function_map.iter().any(|a| a.function.contains("I2C1")));
    }

    #[test]
    fn test_beaglebone_layout() {
        let config = GpioController::beaglebone_gpio_layout();
        assert!(config.alt_function_map.iter().any(|a| a.function.contains("UART4")));
    }

    #[test]
    fn test_empty_state() {
        let state = GpioController::get_state(0, "test");
        assert!(state.pins.is_empty());
    }

    #[test]
    fn test_identify_board_rpi() {
        let pins = vec![
            (1, 3.3), (2, 5.0), (3, 3.3), (4, 5.0),
            (5, 3.3), (6, 0.0), (7, 3.3), (8, 3.3),
            (9, 0.0), (10, 3.3), (11, 3.3), (12, 3.3),
        ];
        let board = GpioController::identify_board(&pins);
        assert!(board.contains("Raspberry"));
    }

    #[test]
    fn test_identify_board_arduino() {
        let pins = vec![(1, 5.0), (2, 5.0), (3, 0.0), (4, 5.0)];
        let board = GpioController::identify_board(&pins);
        assert!(board.contains("Arduino"));
    }

    #[test]
    fn test_gpio_state_serde() {
        let state = GpioController::get_state(4, "BCM2835");
        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(json.contains("GPIO0"));
    }
}
