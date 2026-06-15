use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyLine {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    pub section: String,
    pub lines: Vec<DisassemblyLine>,
    pub total_bytes: usize,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X86_64,
    ARM,
    ARM64,
    Unknown,
}

pub struct Disassembler;

impl Disassembler {
    pub fn disassemble_section(file_path: &str, section: &str) -> Result<DisassemblyResult, String> {
        let bin = crate::binary::BinaryAnalyzer::analyze(file_path)?;
        let _arch_flag = match bin.arch.as_str() {
            "x86_64" => "i386:x86-64",
            "x86" => "i386",
            "ARM64" | "aarch64" => "aarch64",
            "ARM" => "arm",
            _ => return Err(format!("Unsupported arch: {}", bin.arch)),
        };

        let output = Command::new("objdump")
            .args([
                "-d",
                "-M", "intel",
                "--section", section,
                file_path,
            ])
            .output()
            .map_err(|e| format!("objdump failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("objdump error: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines = Self::parse_objdump(&stdout, &bin.arch);
        let total_bytes: usize = lines.iter().map(|l| l.bytes.len()).sum();

        Ok(DisassemblyResult {
            section: section.to_string(),
            lines,
            total_bytes,
            arch: bin.arch,
        })
    }

    pub fn disassemble_function(file_path: &str, function: &str) -> Result<DisassemblyResult, String> {
        let bin = crate::binary::BinaryAnalyzer::analyze(file_path)?;

        let output = Command::new("objdump")
            .args([
                "-d",
                "-M", "intel",
                file_path,
            ])
            .output()
            .map_err(|e| format!("objdump failed: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("objdump error: {}", stderr.trim()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut in_function = false;
        let mut lines = Vec::new();
        let mut total_bytes = 0usize;

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(&format!("<{}>:", function)) || trimmed.starts_with(&format!("<{}>", function)) {
                in_function = true;
                continue;
            }
            if in_function {
                if trimmed.starts_with('<') && trimmed.ends_with(">:") {
                    break;
                }
                if let Some(dl) = Self::parse_line(trimmed) {
                    total_bytes += dl.bytes.len();
                    lines.push(dl);
                }
            }
        }

        Ok(DisassemblyResult {
            section: function.to_string(),
            lines,
            total_bytes,
            arch: bin.arch,
        })
    }

    pub fn disassemble_bytes(bytes: &[u8], arch: &Architecture) -> Result<DisassemblyResult, String> {
        let tmp_file = "/tmp/kraken_disasm_tmp.bin";
        std::fs::write(tmp_file, bytes)
            .map_err(|e| format!("Cannot write tmp file: {}", e))?;

        let _arch_str = match arch {
            Architecture::X86_64 => "i386:x86-64",
            Architecture::X86 => "i386",
            Architecture::ARM64 => "aarch64",
            Architecture::ARM => "arm",
            Architecture::Unknown => return Err("Unknown architecture".to_string()),
        };

        let output = Command::new("objdump")
            .args([
                "-d",
                "-M", "intel",
                "-b", "binary",
                "-m", match arch {
                    Architecture::X86_64 | Architecture::X86 => "i386",
                    Architecture::ARM64 => "aarch64",
                    Architecture::ARM => "arm",
                    Architecture::Unknown => return Err("Unknown architecture".to_string()),
                },
                tmp_file,
            ])
            .output()
            .map_err(|e| format!("objdump failed: {}", e))?;

        let _ = std::fs::remove_file(tmp_file);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines = Self::parse_objdump(&stdout, &format!("{:?}", arch));

        Ok(DisassemblyResult {
            section: "raw".to_string(),
            lines,
            total_bytes: bytes.len(),
            arch: format!("{:?}", arch),
        })
    }

    fn parse_objdump(output: &str, _arch: &str) -> Vec<DisassemblyLine> {
        let re = regex::Regex::new(
            r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s+(\S+)\s+(.+)$"
        ).ok();

        let mut lines = Vec::new();
        for line in output.lines() {
            if let Some(ref re) = re {
                if let Some(caps) = re.captures(line) {
                    let addr_str = caps.get(1).map_or("0", |m| m.as_str());
                    let addr = u64::from_str_radix(addr_str, 16).unwrap_or(0);
                    let bytes_str = caps.get(2).map_or("", |m| m.as_str());
                    let bytes: Vec<u8> = bytes_str.split_whitespace()
                        .filter_map(|b| u8::from_str_radix(b, 16).ok())
                        .collect();
                    let mnemonic = caps.get(3).map_or("", |m| m.as_str()).to_string();
                    let operands = caps.get(4).map_or("", |m| m.as_str()).to_string();
                    lines.push(DisassemblyLine { address: addr, bytes, mnemonic, operands });
                }
            }
        }
        lines
    }

    fn parse_line(line: &str) -> Option<DisassemblyLine> {
        let re = regex::Regex::new(
            r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s+(\S+)\s+(.+)$"
        ).ok()?;
        let caps = re.captures(line)?;
        let addr = u64::from_str_radix(caps.get(1).map_or("0", |m| m.as_str()), 16).ok()?;
        let bytes: Vec<u8> = caps.get(2).map_or("", |m| m.as_str())
            .split_whitespace()
            .filter_map(|b| u8::from_str_radix(b, 16).ok())
            .collect();
        Some(DisassemblyLine {
            address: addr,
            bytes,
            mnemonic: caps.get(3).map_or("", |m| m.as_str()).to_string(),
            operands: caps.get(4).map_or("", |m| m.as_str()).to_string(),
        })
    }
}

pub fn format_disassembly(result: &DisassemblyResult) -> String {
    let mut out = format!("Disassembly of section {} ({} architecture)\n", result.section, result.arch);
    out.push_str(&format!("Total bytes: {}\n\n", result.total_bytes));

    for line in &result.lines {
        let hex_bytes: String = line.bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        out.push_str(&format!("  {:#010x}: {:<20} {:<8} {}\n",
            line.address, hex_bytes, line.mnemonic, line.operands));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_line() {
        let line = DisassemblyLine {
            address: 0x1000,
            bytes: vec![0x48, 0x89, 0xe5],
            mnemonic: "mov".to_string(),
            operands: "rbp, rsp".to_string(),
        };
        assert_eq!(line.address, 0x1000);
        assert_eq!(line.mnemonic, "mov");
        assert_eq!(line.bytes.len(), 3);
    }

    #[test]
    fn test_parse_objdump_line() {
        let line = "  1000:	48 89 e5             	mov    rbp,rsp";
        let parsed = Disassembler::parse_line(line);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.address, 0x1000);
        assert_eq!(parsed.bytes, vec![0x48, 0x89, 0xe5]);
        assert_eq!(parsed.mnemonic, "mov");
    }

    #[test]
    fn test_disassembly_result() {
        let result = DisassemblyResult {
            section: ".text".to_string(),
            lines: vec![
                DisassemblyLine {
                    address: 0x1000,
                    bytes: vec![0x90],
                    mnemonic: "nop".to_string(),
                    operands: String::new(),
                },
            ],
            total_bytes: 1,
            arch: "x86_64".to_string(),
        };
        let formatted = format_disassembly(&result);
        assert!(formatted.contains("nop"));
        assert!(formatted.contains(".text"));
    }

    #[test]
    fn test_disassemble_nonexistent_file() {
        let result = Disassembler::disassemble_section("/tmp/nonexistent", ".text");
        assert!(result.is_err());
    }

    #[test]
    fn test_architecture_display() {
        assert_eq!(format!("{:?}", Architecture::X86_64), "X86_64");
        assert_eq!(format!("{:?}", Architecture::ARM64), "ARM64");
    }
}
