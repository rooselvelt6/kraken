#![forbid(unsafe_code)]

#[cfg(feature = "pcap")]
pub mod arp;
#[cfg(feature = "pcap")]
pub mod capture;
pub mod creds;
pub mod dhcp_spoof;
pub mod dissectors;
#[cfg(feature = "pcap")]
pub mod dns_spoof;
#[cfg(feature = "pcap")]
pub mod mitm;
pub mod packet;
#[cfg(feature = "pcap")]
pub mod pcap_analyzer;
pub mod session;
pub mod sslstrip;

/// Los módulos de captura en vivo requieren la feature `pcap`, que a su vez
/// necesita las cabeceras de desarrollo de libpcap en el sistema.
pub const PCAP_UNAVAILABLE: &str =
    "captura de paquetes no disponible: recompila con `--features pcap` e instala libpcap-dev";
