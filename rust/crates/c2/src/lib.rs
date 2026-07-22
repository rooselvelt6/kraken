#![forbid(unsafe_code)]

pub mod beacon_http;
pub mod beacon_dns;
pub mod beacon_ws;
pub mod beacon_smb;
pub mod task;
pub mod payload;
pub mod session;
pub mod kill;
pub mod proxy;
pub mod malleable;
pub mod error;

pub use beacon_http::HttpBeacon;
pub use beacon_dns::DnsBeacon;
pub use beacon_ws::WsBeacon;
pub use beacon_smb::SmbBeacon;
pub use task::TaskManager;
pub use payload::PayloadStager;
pub use session::SessionManager;
pub use kill::KillSwitch;
pub use proxy::ProxyConfig;
pub use malleable::MalleableEngine;
pub use error::C2Error;
