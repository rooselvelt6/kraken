use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub mode: RouteMode,
    pub tor_enabled: bool,
    pub proxy_chain: Vec<String>,
    pub auto_detect: bool,
    pub kill_switch: bool,
    pub dns_leak_protection: bool,
    pub ipv6_leak_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RouteMode {
    Direct,
    TorOnly,
    ProxyChain,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStatus {
    pub mode: RouteMode,
    pub active: bool,
    pub current_gateway: Option<String>,
    pub public_ip: Option<String>,
    pub tor_circuits: usize,
    pub proxy_count: usize,
    pub dns_leak_protected: bool,
    pub ipv6_disabled: bool,
}

pub struct RouteManager;

impl Default for RouteManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RouteManager {
    pub fn new() -> Self {
        RouteManager
    }

    pub fn anonsurf_config() -> RouteConfig {
        RouteConfig {
            mode: RouteMode::TorOnly,
            tor_enabled: true,
            proxy_chain: vec![],
            auto_detect: true,
            kill_switch: true,
            dns_leak_protection: true,
            ipv6_leak_protection: true,
        }
    }

    pub fn proxychains_config() -> RouteConfig {
        RouteConfig {
            mode: RouteMode::ProxyChain,
            tor_enabled: false,
            proxy_chain: vec![
                "socks5 127.0.0.1 9050".to_string(),
                "socks5 127.0.0.1 9051".to_string(),
            ],
            auto_detect: false,
            kill_switch: false,
            dns_leak_protection: true,
            ipv6_leak_protection: false,
        }
    }

    pub fn get_status(config: &RouteConfig) -> RouteStatus {
        RouteStatus {
            mode: config.mode.clone(),
            active: config.tor_enabled || !config.proxy_chain.is_empty(),
            current_gateway: None,
            public_ip: None,
            tor_circuits: if config.tor_enabled { 3 } else { 0 },
            proxy_count: config.proxy_chain.len(),
            dns_leak_protected: config.dns_leak_protection,
            ipv6_disabled: config.ipv6_leak_protection,
        }
    }

    pub fn enable_kill_switch(config: &mut RouteConfig) {
        config.kill_switch = true;
        config.dns_leak_protection = true;
        config.ipv6_leak_protection = true;
    }

    pub fn disable_ipv6() -> Vec<String> {
        vec![
            "net.ipv6.conf.all.disable_ipv6 = 1".to_string(),
            "net.ipv6.conf.default.disable_ipv6 = 1".to_string(),
            "net.ipv6.conf.lo.disable_ipv6 = 1".to_string(),
        ]
    }

    pub fn configure_dns(use_tor_dns: bool) -> Vec<String> {
        if use_tor_dns {
            vec![
                "nameserver 127.0.0.1".to_string(),
                "DNS resolver: Tor DNS (port 5353)".to_string(),
            ]
        } else {
            vec![
                "nameserver 1.1.1.1".to_string(),
                "nameserver 8.8.8.8".to_string(),
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anonsurf_config() {
        let config = RouteManager::anonsurf_config();
        assert_eq!(config.mode, RouteMode::TorOnly);
        assert!(config.kill_switch);
        assert!(config.dns_leak_protection);
    }

    #[test]
    fn test_proxychains_config() {
        let config = RouteManager::proxychains_config();
        assert_eq!(config.mode, RouteMode::ProxyChain);
        assert_eq!(config.proxy_chain.len(), 2);
    }

    #[test]
    fn test_get_status() {
        let config = RouteManager::anonsurf_config();
        let status = RouteManager::get_status(&config);
        assert!(status.active);
        assert_eq!(status.tor_circuits, 3);
    }

    #[test]
    fn test_enable_kill_switch() {
        let mut config = RouteManager::proxychains_config();
        assert!(!config.kill_switch);
        RouteManager::enable_kill_switch(&mut config);
        assert!(config.kill_switch);
    }

    #[test]
    fn test_disable_ipv6() {
        let cmds = RouteManager::disable_ipv6();
        assert_eq!(cmds.len(), 3);
    }

    #[test]
    fn test_route_serde() {
        let config = RouteManager::anonsurf_config();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("TorOnly"));
    }
}
