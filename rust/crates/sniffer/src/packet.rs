use serde::{Deserialize, Serialize};
use std::fmt;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: DateTime<Utc>,
    pub len: usize,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub eth_type: Option<u16>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub protocol: Option<u8>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub payload: Vec<u8>,
    pub summary: String,
    pub protocol_name: String,
}

impl Default for PacketInfo {
    fn default() -> Self {
        PacketInfo {
            timestamp: Utc::now(),
            len: 0,
            src_mac: None,
            dst_mac: None,
            eth_type: None,
            src_ip: None,
            dst_ip: None,
            protocol: None,
            src_port: None,
            dst_port: None,
            payload: Vec::new(),
            summary: String::new(),
            protocol_name: "unknown".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 14 { return None; }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&data[0..6]);
        src.copy_from_slice(&data[6..12]);
        let ether_type = u16::from_be_bytes([data[12], data[13]]);
        Some(EthernetHeader { dst_mac: dst, src_mac: src, ether_type })
    }

    pub fn src_mac_str(&self) -> String {
        mac_to_string(&self.src_mac)
    }

    pub fn dst_mac_str(&self) -> String {
        mac_to_string(&self.dst_mac)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpPacket {
    pub hw_type: u16,
    pub proto_type: u16,
    pub hw_size: u8,
    pub proto_size: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}

impl ArpPacket {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 { return None; }
        Some(ArpPacket {
            hw_type: u16::from_be_bytes([data[0], data[1]]),
            proto_type: u16::from_be_bytes([data[2], data[3]]),
            hw_size: data[4],
            proto_size: data[5],
            opcode: u16::from_be_bytes([data[6], data[7]]),
            sender_mac: {
                let mut m = [0u8; 6]; m.copy_from_slice(&data[8..14]); m
            },
            sender_ip: {
                let mut m = [0u8; 4]; m.copy_from_slice(&data[14..18]); m
            },
            target_mac: {
                let mut m = [0u8; 6]; m.copy_from_slice(&data[18..24]); m
            },
            target_ip: {
                let mut m = [0u8; 4]; m.copy_from_slice(&data[24..28]); m
            },
        })
    }

    pub fn is_request(&self) -> bool { self.opcode == 1 }
    pub fn is_reply(&self) -> bool { self.opcode == 2 }
    pub fn sender_ip_str(&self) -> String { ip_to_string(&self.sender_ip) }
    pub fn target_ip_str(&self) -> String { ip_to_string(&self.target_ip) }
    pub fn sender_mac_str(&self) -> String { mac_to_string(&self.sender_mac) }
    pub fn target_mac_str(&self) -> String { mac_to_string(&self.target_mac) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

impl Ipv4Header {
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 20 { return None; }
        let version_ihl = data[0];
        let ihl = (version_ihl & 0x0f) as usize;
        if data.len() < ihl * 4 { return None; }
        Some((Ipv4Header {
            version: version_ihl >> 4,
            ihl: ihl as u8,
            dscp: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: data[6] >> 5,
            fragment_offset: u16::from_be_bytes([data[6] & 0x1f, data[7]]),
            ttl: data[8],
            protocol: data[9],
            header_checksum: u16::from_be_bytes([data[10], data[11]]),
            src_ip: { let mut m = [0u8; 4]; m.copy_from_slice(&data[12..16]); m },
            dst_ip: { let mut m = [0u8; 4]; m.copy_from_slice(&data[16..20]); m },
        }, ihl * 4))
    }

    pub fn src_ip_str(&self) -> String { ip_to_string(&self.src_ip) }
    pub fn dst_ip_str(&self) -> String { ip_to_string(&self.dst_ip) }

    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            47 => "GRE",
            50 => "ESP",
            51 => "AH",
            89 => "OSPF",
            132 => "SCTP",
            _ => "IP",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 20 { return None; }
        let data_offset = (data[12] >> 4) as usize;
        if data.len() < data_offset * 4 { return None; }
        Some((TcpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset: data_offset as u8,
            flags: data[13],
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_pointer: u16::from_be_bytes([data[18], data[19]]),
        }, data_offset * 4))
    }

    pub fn flags_str(&self) -> String {
        let mut s = String::new();
        if self.flags & 0x01 != 0 { s.push_str("FIN "); }
        if self.flags & 0x02 != 0 { s.push_str("SYN "); }
        if self.flags & 0x04 != 0 { s.push_str("RST "); }
        if self.flags & 0x08 != 0 { s.push_str("PSH "); }
        if self.flags & 0x10 != 0 { s.push_str("ACK "); }
        if self.flags & 0x20 != 0 { s.push_str("URG "); }
        s.trim().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 { return None; }
        Some((UdpHeader {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            checksum: u16::from_be_bytes([data[6], data[7]]),
        }, 8))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

impl DnsHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 12 { return None; }
        Some((DnsHeader {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            questions: u16::from_be_bytes([data[4], data[5]]),
            answers: u16::from_be_bytes([data[6], data[7]]),
            authority: u16::from_be_bytes([data[8], data[9]]),
            additional: u16::from_be_bytes([data[10], data[11]]),
        }, 12))
    }

    pub fn is_response(&self) -> bool { self.flags & 0x8000 != 0 }
    pub fn is_query(&self) -> bool { !self.is_response() }
    pub fn opcode(&self) -> u8 { ((self.flags >> 11) & 0x0f) as u8 }
    pub fn rcode(&self) -> u8 { (self.flags & 0x0f) as u8 }
}

pub fn parse_dns_questions(data: &[u8], count: u16) -> Vec<String> {
    let mut names = Vec::new();
    let mut offset = 0;
    for _ in 0..count {
        if offset >= data.len() { break; }
        if let Some((name, adv)) = parse_dns_name(data, offset) {
            names.push(name);
            offset = adv + 4;
        } else {
            break;
        }
    }
    names
}

pub(crate) fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut jumped = false;
    let mut jump_offset = 0;

    loop {
        if offset >= data.len() { return None; }
        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= data.len() { return None; }
            let ptr = ((len & 0x3f) << 8) | data[offset + 1] as usize;
            if !jumped {
                jump_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }
        offset += 1;
        if offset + len > data.len() { return None; }
        if !name.is_empty() { name.push('.'); }
        name.push_str(&String::from_utf8_lossy(&data[offset..offset + len]));
        offset += len;
    }

    if jumped {
        Some((name, jump_offset))
    } else {
        Some((name, offset))
    }
}

pub fn mac_to_string(mac: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

pub fn ip_to_string(ip: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

pub fn parse_packet(data: &[u8], len: usize) -> PacketInfo {
    let mut info = PacketInfo::default();
    info.len = len;
    info.payload = data.to_vec();

    let eth = EthernetHeader::parse(data);
    if let Some(eth) = eth {
        info.src_mac = Some(eth.src_mac_str());
        info.dst_mac = Some(eth.dst_mac_str());
        info.eth_type = Some(eth.ether_type);

        let ip_offset = 14;
        if eth.ether_type == 0x0800 && data.len() > ip_offset {
            if let Some((ip, ip_hdr_len)) = Ipv4Header::parse(&data[ip_offset..]) {
                info.src_ip = Some(ip.src_ip_str());
                info.dst_ip = Some(ip.dst_ip_str());
                info.protocol = Some(ip.protocol);
                info.protocol_name = ip.protocol_name().to_string();

                let transport_offset = ip_offset + ip_hdr_len;
                match ip.protocol {
                    6 => {
                        if let Some((tcp, tcp_hdr_len)) = TcpHeader::parse(&data[transport_offset..]) {
                            info.src_port = Some(tcp.src_port);
                            info.dst_port = Some(tcp.dst_port);
                            let app_offset = transport_offset + tcp_hdr_len;
                            if app_offset < data.len() {
                                info.payload = data[app_offset..].to_vec();
                            }
                            let src = info.src_ip.as_deref().unwrap_or("?");
                            let dst = info.dst_ip.as_deref().unwrap_or("?");
                            let port_name = match (tcp.src_port, tcp.dst_port) {
                                (80, _) | (_, 80) => "HTTP",
                                (443, _) | (_, 443) => "HTTPS",
                                (22, _) | (_, 22) => "SSH",
                                (21, _) | (_, 21) => "FTP",
                                (25, _) | (_, 25) => "SMTP",
                                (110, _) | (_, 110) => "POP3",
                                (143, _) | (_, 143) => "IMAP",
                                _ => "TCP",
                            };
                            info.protocol_name = port_name.to_string();
                            info.summary = format!("TCP {}:{} -> {}:{} [{}]",
                                src, tcp.src_port, dst, tcp.dst_port, tcp.flags_str());
                        }
                    }
                    17 => {
                        if let Some((udp, _)) = UdpHeader::parse(&data[transport_offset..]) {
                            info.src_port = Some(udp.src_port);
                            info.dst_port = Some(udp.dst_port);
                            let app_offset = transport_offset + 8;
                            if app_offset < data.len() {
                                info.payload = data[app_offset..].to_vec();
                            }
                            let src = info.src_ip.as_deref().unwrap_or("?");
                            let dst = info.dst_ip.as_deref().unwrap_or("?");
                            let port_name = match (udp.src_port, udp.dst_port) {
                                (53, _) | (_, 53) => "DNS",
                                (67, _) | (68, _) | (_, 67) | (_, 68) => "DHCP",
                                (161, _) | (_, 161) => "SNMP",
                                (123, _) | (_, 123) => "NTP",
                                _ => "UDP",
                            };
                            info.protocol_name = port_name.to_string();
                            info.summary = format!("UDP {}:{} -> {}:{}",
                                src, udp.src_port, dst, udp.dst_port);
                        }
                    }
                    1 => {
                        info.summary = format!("ICMP {} -> {}",
                            info.src_ip.as_deref().unwrap_or("?"),
                            info.dst_ip.as_deref().unwrap_or("?"));
                        info.protocol_name = "ICMP".to_string();
                    }
                    _ => {
                        let src = info.src_ip.as_deref().unwrap_or("?");
                        let dst = info.dst_ip.as_deref().unwrap_or("?");
                        info.summary = format!("{} {} -> {}", ip.protocol_name(), src, dst);
                    }
                }
            }
        } else if eth.ether_type == 0x0806 && data.len() >= 42 {
            if let Some(arp) = ArpPacket::parse(&data[ip_offset..]) {
                info.protocol_name = "ARP".to_string();
                let op = if arp.is_request() { "REQUEST" } else { "REPLY" };
                info.summary = format!("ARP {} who-has {} tell {} ({})",
                    op, arp.target_ip_str(), arp.sender_ip_str(), arp.sender_mac_str());
                info.payload = data[ip_offset..].to_vec();
            }
        } else if eth.ether_type == 0x8100 {
            info.protocol_name = "VLAN".to_string();
        } else if eth.ether_type == 0x86DD {
            info.protocol_name = "IPv6".to_string();
        }
    }

    if info.summary.is_empty() {
        info.summary = format!("Frame {} bytes", len);
    }

    info
}

pub fn packet_hex_dump(data: &[u8], max_len: usize) -> String {
    let len = data.len().min(max_len);
    let mut result = String::new();
    for (i, chunk) in data[..len].chunks(16).enumerate() {
        result.push_str(&format!("{:08x}  ", i * 16));
        for (j, byte) in chunk.iter().enumerate() {
            result.push_str(&format!("{:02x} ", byte));
            if j == 7 { result.push(' '); }
        }
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                result.push_str("   ");
            }
            if chunk.len() <= 8 { result.push(' '); }
        }
        result.push(' ');
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                result.push(byte as char);
            } else {
                result.push('.');
            }
        }
        result.push('\n');
    }
    result
}

impl fmt::Display for PacketInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} ({})", self.protocol_name, self.summary, self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_parse() {
        let data = [0xffu8; 14];
        let eth = EthernetHeader::parse(&data).unwrap();
        assert_eq!(eth.ether_type, 0xffff);
    }

    #[test]
    fn test_mac_to_string() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(mac_to_string(&mac), "00:11:22:33:44:55");
    }

    #[test]
    fn test_ip_to_string() {
        let ip = [192, 168, 1, 1];
        assert_eq!(ip_to_string(&ip), "192.168.1.1");
    }

    #[test]
    fn test_arp_parse_request() {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x00, 0x01]); // hw_type = Ethernet
        data.extend_from_slice(&[0x08, 0x00]); // proto_type = IPv4
        data.push(6); // hw_size
        data.push(4); // proto_size
        data.extend_from_slice(&[0x00, 0x01]); // opcode = REQUEST
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // sender_mac
        data.extend_from_slice(&[192, 168, 1, 10]); // sender_ip
        data.extend_from_slice(&[0x00; 6]); // target_mac
        data.extend_from_slice(&[192, 168, 1, 1]); // target_ip

        let arp = ArpPacket::parse(&data).unwrap();
        assert!(arp.is_request());
        assert!(!arp.is_reply());
        assert_eq!(arp.sender_ip_str(), "192.168.1.10");
        assert_eq!(arp.target_ip_str(), "192.168.1.1");
    }

    #[test]
    fn test_ipv4_parse() {
        let data = vec![0x45, 0x00, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x00,
                            0x40, 0x06, 0x00, 0x00, 192, 168, 1, 1,
                            192, 168, 1, 2];
        let (ip, hdr_len) = Ipv4Header::parse(&data).unwrap();
        assert_eq!(ip.version, 4);
        assert_eq!(ip.ihl, 5);
        assert_eq!(ip.protocol, 6);
        assert_eq!(ip.src_ip_str(), "192.168.1.1");
        assert_eq!(ip.dst_ip_str(), "192.168.1.2");
        assert_eq!(hdr_len, 20);
    }

    #[test]
    fn test_tcp_parse() {
        let data = vec![0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
                            0x00, 0x00, 0x00, 0x02, 0x50, 0x18, 0x20, 0x00,
                            0x00, 0x00, 0x00, 0x00];
        let (tcp, hdr_len) = TcpHeader::parse(&data).unwrap();
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 443);
        assert_eq!(hdr_len, 20);
    }

    #[test]
    fn test_udp_parse() {
        let data = [0x00, 0x35, 0x00, 0x50, 0x00, 0x10, 0x00, 0x00];
        let (udp, _) = UdpHeader::parse(&data).unwrap();
        assert_eq!(udp.src_port, 53);
        assert_eq!(udp.dst_port, 80);
        assert_eq!(udp.length, 16);
    }

    #[test]
    fn test_dns_header_parse() {
        let data = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
                    0x00, 0x00, 0x00, 0x00];
        let (dns, _) = DnsHeader::parse(&data).unwrap();
        assert_eq!(dns.id, 0x1234);
        assert_eq!(dns.questions, 1);
        assert_eq!(dns.answers, 1);
        assert!(dns.is_response());
    }

    #[test]
    fn test_dns_name_parse() {
        let data = vec![3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        let (name, adv) = parse_dns_name(&data, 0).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(adv, data.len());
    }

    #[test]
    fn test_hex_dump() {
        let data = b"hello world";
        let dump = packet_hex_dump(data, 20);
        assert!(dump.contains("68 65 6c 6c 6f"));
    }

    #[test]
    fn test_tcp_flags() {
        let data = vec![0x00, 0x50, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
                            0x00, 0x00, 0x00, 0x02, 0x50, 0x02, 0x20, 0x00,
                            0x00, 0x00, 0x00, 0x00];
        let (tcp, _) = TcpHeader::parse(&data).unwrap();
        assert_eq!(tcp.flags_str(), "SYN");
    }

    #[test]
    fn test_packet_short_data() {
        let info = parse_packet(&[], 0);
        assert_eq!(info.summary, "Frame 0 bytes");
    }
}
