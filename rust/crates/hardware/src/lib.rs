#![forbid(unsafe_code)]

pub mod firmware;
pub mod entropy;
pub mod diff;
pub mod uart;
pub mod sdr;
pub mod gpio;
pub mod jtag;
pub mod flash;
pub mod iot_fuzz;
pub mod credentials;
pub mod llm_audit;

pub use firmware::FirmwareExtractor;
pub use entropy::EntropyScanner;
pub use diff::FirmwareDiffer;
pub use uart::UartDetector;
pub use sdr::SdrScanner;
pub use gpio::GpioController;
pub use jtag::JtagDetector;
pub use flash::FlashReader;
pub use iot_fuzz::IotProtocolFuzzer;
pub use credentials::CredentialScanner;
pub use llm_audit::LlmFirmwareAuditor;
