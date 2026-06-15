use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DhcpSpoofConfig {
    pub interface: String,
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub router_ip: Ipv4Addr,
    pub dns_server: Ipv4Addr,
    pub lease_time: u32,
    pub pool_start: Ipv4Addr,
    pub pool_end: Ipv4Addr,
    pub domain_name: Option<String>,
}

impl Default for DhcpSpoofConfig {
    fn default() -> Self {
        DhcpSpoofConfig {
            interface: String::new(),
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router_ip: Ipv4Addr::new(192, 168, 1, 1),
            dns_server: Ipv4Addr::new(8, 8, 8, 8),
            lease_time: 86400,
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            domain_name: None,
        }
    }
}

pub struct DhcpSpoofServer {
    pub config: DhcpSpoofConfig,
    pub leases: HashMap<String, Ipv4Addr>,
    #[allow(dead_code)]
    next_ip: u32,
}

impl DhcpSpoofServer {
    pub fn new(config: DhcpSpoofConfig) -> Self {
        let next_ip = u32::from_be_bytes(config.pool_start.octets());
        DhcpSpoofServer {
            config,
            leases: HashMap::new(),
            next_ip,
        }
    }

    pub fn handle_discover(&mut self, chaddr: &[u8; 6], xid: u32) -> Vec<u8> {
        let offered_ip = self.leases.get(&mac_str(chaddr))
            .copied()
            .unwrap_or_else(|| self.allocate_ip());

        if offered_ip.octets() == [0; 4] {
            return Vec::new();
        }

        self.build_dhcp_offer(chaddr, offered_ip, xid)
    }

    pub fn handle_request(&mut self, chaddr: &[u8; 6], requested_ip: Option<Ipv4Addr>, xid: u32, server_ip: Option<Ipv4Addr>) -> Vec<u8> {
        let ip = requested_ip.unwrap_or_else(|| {
            self.leases.get(&mac_str(chaddr))
                .copied()
                .unwrap_or_else(|| self.allocate_ip())
        });

        if ip.octets() == [0; 4] {
            return Vec::new();
        }

        if let Some(srv) = server_ip {
            if srv != self.config.server_ip {
                return Vec::new();
            }
        }

        self.leases.insert(mac_str(chaddr), ip);
        self.build_dhcp_ack(chaddr, ip, xid)
    }

    fn allocate_ip(&mut self) -> Ipv4Addr {
        let start = u32::from_be_bytes(self.config.pool_start.octets());
        let end = u32::from_be_bytes(self.config.pool_end.octets());

        for offset in 0..=(end - start) {
            let candidate = start + offset;
            let ip_bytes = candidate.to_be_bytes();
            let ip = Ipv4Addr::from(ip_bytes);
            if !self.leases.values().any(|v| *v == ip) {
                return ip;
            }
        }
        Ipv4Addr::new(0, 0, 0, 0)
    }

    fn build_dhcp_offer(&self, chaddr: &[u8; 6], yiaddr: Ipv4Addr, xid: u32) -> Vec<u8> {
        self.build_dhcp_message(2, chaddr, yiaddr, xid, 2)
    }

    fn build_dhcp_ack(&self, chaddr: &[u8; 6], yiaddr: Ipv4Addr, xid: u32) -> Vec<u8> {
        self.build_dhcp_message(2, chaddr, yiaddr, xid, 5)
    }

    fn build_dhcp_message(&self, op: u8, chaddr: &[u8; 6], yiaddr: Ipv4Addr, xid: u32, msg_type: u8) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(300);
        pkt.push(op);
        pkt.push(1);
        pkt.push(6);
        pkt.push(0);
        pkt.extend_from_slice(&xid.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x80, 0x00]);
        pkt.extend_from_slice(&[0u8; 4]);
        pkt.extend_from_slice(&yiaddr.octets());
        pkt.extend_from_slice(&self.config.server_ip.octets());
        pkt.extend_from_slice(&[0u8; 4]);
        pkt.extend_from_slice(chaddr.as_slice());
        pkt.resize(240, 0);
        pkt.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        pkt.extend_from_slice(&[53, 1, msg_type]);
        pkt.extend_from_slice(&[1, 4]);
        pkt.extend_from_slice(&self.config.subnet_mask.octets());
        pkt.extend_from_slice(&[3, 4]);
        pkt.extend_from_slice(&self.config.router_ip.octets());
        pkt.extend_from_slice(&[6, 4]);
        pkt.extend_from_slice(&self.config.dns_server.octets());
        pkt.extend_from_slice(&[51, 4]);
        pkt.extend_from_slice(&self.config.lease_time.to_be_bytes());
        pkt.extend_from_slice(&[54, 4]);
        pkt.extend_from_slice(&self.config.server_ip.octets());

        if let Some(domain) = &self.config.domain_name {
            if domain.len() < 255 {
                pkt.extend_from_slice(&[15, domain.len() as u8]);
                pkt.extend_from_slice(domain.as_bytes());
            }
        }

        pkt.push(255);
        pkt
    }
}

fn mac_str(mac: &[u8; 6]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_config_default() {
        let config = DhcpSpoofConfig::default();
        assert_eq!(config.server_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.lease_time, 86400);
    }

    #[test]
    fn test_dhcp_server_new() {
        let server = DhcpSpoofServer::new(DhcpSpoofConfig::default());
        assert!(server.leases.is_empty());
    }

    #[test]
    fn test_dhcp_offer() {
        let mut server = DhcpSpoofServer::new(DhcpSpoofConfig::default());
        let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let offer = server.handle_discover(&chaddr, 0x12345678);
        assert!(!offer.is_empty());
        assert_eq!(offer[0], 2);
        assert_eq!(&offer[4..8], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(&offer[16..20], &[192, 168, 1, 100]);
    }

    #[test]
    fn test_dhcp_ack() {
        let mut server = DhcpSpoofServer::new(DhcpSpoofConfig::default());
        let chaddr = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let ack = server.handle_request(&chaddr, Some(ip), 0x12345678, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!ack.is_empty());
        assert_eq!(&ack[16..20], &[192, 168, 1, 100]);
        assert!(server.leases.contains_key(&"aabbccddeeff".to_string()));
    }

    #[test]
    fn test_dhcp_ack_wrong_server() {
        let mut server = DhcpSpoofServer::new(DhcpSpoofConfig::default());
        let chaddr = [0xaa; 6];
        let ack = server.handle_request(&chaddr, None, 0, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(ack.is_empty());
    }

    #[test]
    fn test_allocate_ip() {
        let mut server = DhcpSpoofServer::new(DhcpSpoofConfig::default());
        let ip = server.allocate_ip();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 100));
        server.leases.insert("test".to_string(), ip);
        let ip2 = server.allocate_ip();
        assert_eq!(ip2, Ipv4Addr::new(192, 168, 1, 101));
    }

    #[test]
    fn test_dhcp_server_offer_includes_options() {
        let mut server = DhcpSpoofServer::new(DhcpSpoofConfig::default());
        let chaddr = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let offer = server.handle_discover(&chaddr, 0xdeadbeef);
        assert!(offer.windows(4).any(|w| w == [0x63, 0x82, 0x53, 0x63]));
    }
}
