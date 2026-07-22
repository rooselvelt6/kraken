#![forbid(unsafe_code)]

pub mod osv;
pub mod github;
pub mod nvd;
pub mod cis;
pub mod license;
pub mod sbom;
pub mod slsa;
pub mod policy;
pub mod typosquat;
pub mod risk;
pub mod mcp_trust;

pub use osv::OsvClient;
pub use github::GithubAdvisoryClient;
pub use nvd::NvdClient;
pub use cis::CisScanner;
pub use license::LicenseChecker;
pub use sbom::SbomDiffer;
pub use slsa::SlsaVerifier;
pub use policy::PolicyEngine;
pub use typosquat::TyposquatDetector;
pub use risk::DependencyRiskScorer;
pub use mcp_trust::McpTrustEvaluator;
