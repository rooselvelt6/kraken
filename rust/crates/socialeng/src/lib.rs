#![forbid(unsafe_code)]

pub mod clone;
pub mod harvest;
pub mod templates;
pub mod email;
pub mod qrcode;
pub mod usb;
pub mod proxy;
pub mod sms;
pub mod campaign;

pub use clone::SiteCloner;
pub use harvest::CredHarvester;
pub use templates::{LoginTemplate, PretextTemplate};
pub use email::PhishMailer;
pub use qrcode::QrPhish;
pub use usb::UsbDropper;
pub use proxy::EvilginxProxy;
pub use sms::SmsPhisher;
pub use campaign::CampaignTracker;
