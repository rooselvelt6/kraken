use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothDevice {
    pub mac: String,
    pub name: String,
    pub rssi: Option<i16>,
    pub device_class: String,
    pub paired: bool,
    pub trusted: bool,
    pub connected: bool,
    pub services: Vec<String>,
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleService {
    pub uuid: String,
    pub name: String,
    pub primary: bool,
    pub characteristics: Vec<BleCharacteristic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleCharacteristic {
    pub uuid: String,
    pub name: String,
    pub properties: Vec<String>,
    pub readable: bool,
    pub writable: bool,
    pub notify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleDevice {
    pub mac: String,
    pub name: String,
    pub rssi: Option<i16>,
    pub services: Vec<BleService>,
    pub manufacturer_data: String,
    pub tx_power: Option<i16>,
    pub connectable: bool,
}

pub struct BluetoothScanner;

impl BluetoothScanner {
    pub fn scan_classic(timeout_secs: u64) -> Result<Vec<BluetoothDevice>, String> {
        let _ = Command::new("hcitool")
            .args(["scan", "--flush"])
            .output();

        let output = Command::new("hcitool")
            .args(["scan"])
            .output()
            .map_err(|e| format!("hcitool scan failed: {}", e))?;

        let mut devices = Vec::new();
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.splitn(2, '\t').collect();
            if parts.len() >= 2 {
                let mac = parts[0].trim().to_string();
                let name = parts[1].trim().to_string();
                let dev_info = Self::device_info(&mac);

                devices.push(BluetoothDevice {
                    mac,
                    name,
                    rssi: None,
                    device_class: dev_info.0,
                    paired: dev_info.1,
                    trusted: dev_info.2,
                    connected: dev_info.3,
                    services: Vec::new(),
                    profiles: Vec::new(),
                });
            }
        }

        if devices.is_empty() {
            let output = Command::new("bluetoothctl")
                .args(["--timeout", &timeout_secs.to_string(), "scan", "on"])
                .output()
                .map_err(|e| format!("bluetoothctl scan failed: {}", e))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("Device") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        devices.push(BluetoothDevice {
                            mac: parts[1].to_string(),
                            name: parts[2..].join(" "),
                            rssi: None,
                            device_class: String::new(),
                            paired: false,
                            trusted: false,
                            connected: false,
                            services: Vec::new(),
                            profiles: Vec::new(),
                        });
                    }
                }
            }
        }

        if devices.is_empty() {
            return Err("No Bluetooth devices found or Bluetooth adapter not available".to_string());
        }

        Ok(devices)
    }

    pub fn scan_ble(timeout_secs: u64) -> Result<Vec<BleDevice>, String> {
        let _ = Command::new("hcitool")
            .args(["lescan", "--duplicates"])
            .spawn();

        std::thread::sleep(std::time::Duration::from_secs(timeout_secs));

        let _ = Command::new("hcitool")
            .args(["lecc"])
            .output();

        let output = Command::new("hcitool")
            .args(["lescan"])
            .output();

        let stdout = match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(_) => {
                let _ = Command::new("bluetoothctl")
                    .args(["--timeout", &timeout_secs.to_string(), "scan", "on"])
                    .output();
                String::new()
            }
        };

        let mut devices = Vec::new();
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() >= 2 && parts[0].contains(':') {
                devices.push(BleDevice {
                    mac: parts[0].trim().to_string(),
                    name: parts[1].trim().to_string(),
                    rssi: None,
                    services: Vec::new(),
                    manufacturer_data: String::new(),
                    tx_power: None,
                    connectable: false,
                });
            }
        }

        Ok(devices)
    }

    pub fn device_info(mac: &str) -> (String, bool, bool, bool) {
        let output = Command::new("bluetoothctl")
            .args(["info", mac])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let mut dev_class = String::new();
        let mut paired = false;
        let mut trusted = false;
        let mut connected = false;

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Class:") {
                dev_class = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
            } else if trimmed.starts_with("Paired:") {
                paired = trimmed.contains("yes");
            } else if trimmed.starts_with("Trusted:") {
                trusted = trimmed.contains("yes");
            } else if trimmed.starts_with("Connected:") {
                connected = trimmed.contains("yes");
            }
        }

        (dev_class, paired, trusted, connected)
    }

    pub fn list_adapters() -> Vec<String> {
        let output = Command::new("hciconfig")
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        output.lines()
            .filter(|l| l.contains(":"))
            .filter_map(|l| l.split_whitespace().next())
            .map(|s| s.trim_end_matches(':').to_string())
            .collect()
    }

    pub fn adapter_power(adapter: &str, on: bool) -> Result<(), String> {
        let state = if on { "up" } else { "down" };
        Command::new("hciconfig")
            .args([adapter, state])
            .output()
            .map(|_| ())
            .map_err(|e| format!("Failed to set adapter power: {}", e))
    }

    pub fn inquire_devices() -> Vec<BluetoothDevice> {
        let output = Command::new("hcitool")
            .args(["inquire"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let mut devices = Vec::new();
        let mut current_mac = String::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.contains(':') {
                current_mac = trimmed.split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string();
            } else if trimmed.starts_with("Class:") {
                let dev_class = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
                devices.push(BluetoothDevice {
                    mac: current_mac.clone(),
                    name: String::new(),
                    rssi: None,
                    device_class: dev_class,
                    paired: false,
                    trusted: false,
                    connected: false,
                    services: Vec::new(),
                    profiles: Vec::new(),
                });
            }
        }

        devices
    }

    pub fn name_to_mac(name: &str) -> Option<String> {
        let devices = Self::scan_classic(10).ok()?;
        devices.iter()
            .find(|d| d.name.to_lowercase() == name.to_lowercase())
            .map(|d| d.mac.clone())
    }
}

pub fn format_classic_devices(devices: &[BluetoothDevice]) -> String {
    if devices.is_empty() {
        return "No Bluetooth devices found.".to_string();
    }

    let mut out = format!("Bluetooth Classic Devices ({} found)\n\n", devices.len());
    for (i, dev) in devices.iter().enumerate() {
        out.push_str(&format!("{}. {} ({})\n", i + 1, dev.name, dev.mac));
        if !dev.device_class.is_empty() {
            out.push_str(&format!("   Class: {}\n", dev.device_class));
        }
        if dev.paired {
            out.push_str("   Paired: yes\n");
        }
        if dev.connected {
            out.push_str("   Connected: yes\n");
        }
    }
    out
}

pub fn format_ble_devices(devices: &[BleDevice]) -> String {
    if devices.is_empty() {
        return "No BLE devices found.".to_string();
    }

    let mut out = format!("BLE Devices ({} found)\n\n", devices.len());
    for (i, dev) in devices.iter().enumerate() {
        out.push_str(&format!("{}. {} ({})\n", i + 1, dev.name, dev.mac));
        if let Some(rssi) = dev.rssi {
            out.push_str(&format!("   RSSI: {} dBm\n", rssi));
        }
        if !dev.services.is_empty() {
            out.push_str(&format!("   Services: {}\n", dev.services.len()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bluetooth_device_struct() {
        let dev = BluetoothDevice {
            mac: "00:11:22:33:44:55".to_string(),
            name: "TestPhone".to_string(),
            rssi: Some(-60),
            device_class: "Smartphone".to_string(),
            paired: false,
            trusted: false,
            connected: false,
            services: vec!["0x1105".to_string()],
            profiles: vec!["AVRCP".to_string()],
        };
        assert_eq!(dev.mac, "00:11:22:33:44:55");
        assert_eq!(dev.name, "TestPhone");
        assert_eq!(dev.rssi, Some(-60));
        assert_eq!(dev.services.len(), 1);
    }

    #[test]
    fn test_ble_device_struct() {
        let chr = BleCharacteristic {
            uuid: "0000{2a37-0000-1000-8000-00805f9b34fb}".to_string(),
            name: "Heart Rate".to_string(),
            properties: vec!["Notify".to_string()],
            readable: false,
            writable: false,
            notify: true,
        };
        let svc = BleService {
            uuid: "0000180d-0000-1000-8000-00805f9b34fb".to_string(),
            name: "Heart Rate".to_string(),
            primary: true,
            characteristics: vec![chr],
        };
        let dev = BleDevice {
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            name: "HeartMonitor".to_string(),
            rssi: Some(-75),
            services: vec![svc],
            manufacturer_data: String::new(),
            tx_power: Some(0),
            connectable: true,
        };
        assert_eq!(dev.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(dev.name, "HeartMonitor");
        assert!(dev.connectable);
    }

    #[test]
    fn test_format_classic_empty() {
        let formatted = format_classic_devices(&[]);
        assert_eq!(formatted, "No Bluetooth devices found.");
    }

    #[test]
    fn test_format_classic_with_devices() {
        let devices = vec![BluetoothDevice {
            mac: "00:11:22:33:44:55".to_string(),
            name: "Test".to_string(),
            rssi: Some(-50),
            device_class: "Computer".to_string(),
            paired: true,
            trusted: false,
            connected: false,
            services: vec![],
            profiles: vec![],
        }];
        let formatted = format_classic_devices(&devices);
        assert!(formatted.contains("Test"));
        assert!(formatted.contains("00:11:22:33:44:55"));
        assert!(formatted.contains("Paired"));
    }

    #[test]
    fn test_format_ble_empty() {
        let formatted = format_ble_devices(&[]);
        assert_eq!(formatted, "No BLE devices found.");
    }

    #[test]
    fn test_ble_characteristic_properties() {
        let chr = BleCharacteristic {
            uuid: "test-uuid".to_string(),
            name: "Test".to_string(),
            properties: vec!["Read".to_string(), "Write".to_string(), "Notify".to_string()],
            readable: true,
            writable: true,
            notify: true,
        };
        assert!(chr.readable);
        assert!(chr.writable);
        assert!(chr.notify);
        assert_eq!(chr.properties.len(), 3);
    }

    #[test]
    fn test_bluetooth_services() {
        let mut dev = BluetoothDevice {
            mac: "11:22:33:44:55:66".to_string(),
            name: "Speaker".to_string(),
            rssi: None,
            device_class: "Audio".to_string(),
            paired: false,
            trusted: false,
            connected: false,
            services: vec![],
            profiles: vec![],
        };
        assert!(dev.services.is_empty());
        dev.services.push("0x110B".to_string());
        assert_eq!(dev.services.len(), 1);
    }
}
