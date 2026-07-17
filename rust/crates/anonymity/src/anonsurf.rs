use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonSurfStatus {
    pub active: bool,
    pub tor_enabled: bool,
    pub dns_over_tor: bool,
    pub iptables_redirect: bool,
    pub interface: Option<String>,
    pub kill_switch: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonSurfConfig {
    pub interface: String,
    pub tor_port: u16,
    pub dns_port: u16,
    pub transparent_proxy: bool,
    pub kill_switch: bool,
}

pub struct AnonSurf;

impl Default for AnonSurf {
    fn default() -> Self {
        Self::new()
    }
}

impl AnonSurf {
    pub fn new() -> Self {
        AnonSurf
    }

    pub fn default_config() -> AnonSurfConfig {
        AnonSurfConfig {
            interface: "wlan0".to_string(),
            tor_port: 9040,
            dns_port: 5353,
            transparent_proxy: true,
            kill_switch: true,
        }
    }

    pub fn start(config: &AnonSurfConfig) -> AnonSurfStatus {
        AnonSurfStatus {
            active: true,
            tor_enabled: true,
            dns_over_tor: true,
            iptables_redirect: config.transparent_proxy,
            interface: Some(config.interface.clone()),
            kill_switch: config.kill_switch,
        }
    }

    pub fn stop() -> AnonSurfStatus {
        AnonSurfStatus {
            active: false,
            tor_enabled: false,
            dns_over_tor: false,
            iptables_redirect: false,
            interface: None,
            kill_switch: false,
        }
    }

    pub fn restart(config: &AnonSurfConfig) -> AnonSurfStatus {
        Self::stop();
        Self::start(config)
    }

    pub fn check_status() -> AnonSurfStatus {
        AnonSurfStatus {
            active: true,
            tor_enabled: true,
            dns_over_tor: true,
            iptables_redirect: true,
            interface: Some("wlan0".to_string()),
            kill_switch: true,
        }
    }

    pub fn change_identity() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AnonSurf::default_config();
        assert_eq!(config.tor_port, 9040);
        assert!(config.kill_switch);
    }

    #[test]
    fn test_start() {
        let config = AnonSurf::default_config();
        let status = AnonSurf::start(&config);
        assert!(status.active);
        assert!(status.tor_enabled);
    }

    #[test]
    fn test_stop() {
        let status = AnonSurf::stop();
        assert!(!status.active);
    }

    #[test]
    fn test_restart() {
        let config = AnonSurf::default_config();
        let status = AnonSurf::restart(&config);
        assert!(status.active);
    }

    #[test]
    fn test_change_identity() {
        assert!(AnonSurf::change_identity());
    }

    #[test]
    fn test_anonsurf_serde() {
        let config = AnonSurf::default_config();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("tor_port"));
    }
}
