use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareImage {
    pub path: String,
    pub size: u64,
    pub detected_fs: Vec<String>,
    pub files: Vec<FirmwareFile>,
    pub entropy: f64,
    pub sections: Vec<FirmwareSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareFile {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub compressed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareSection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    pub section_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionResult {
    pub image: FirmwareImage,
    pub extracted_count: usize,
    pub total_size: u64,
}

pub struct FirmwareExtractor;

impl Default for FirmwareExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl FirmwareExtractor {
    pub fn new() -> Self {
        FirmwareExtractor
    }

    pub fn analyze(data: &[u8], path: &str) -> FirmwareImage {
        let size = data.len() as u64;
        let fs_types = Self::detect_filesystems(data);
        let sections = Self::detect_sections(data);
        let entropy = Self::calculate_entropy(data);
        let files = Self::candidate_files(data, &fs_types);

        FirmwareImage {
            path: path.to_string(),
            size,
            detected_fs: fs_types,
            files,
            entropy,
            sections,
        }
    }

    pub fn extract(data: &[u8], path: &str) -> ExtractionResult {
        let image = Self::analyze(data, path);
        let extracted_count = image.files.len();
        let total_size = image.files.iter().map(|f| f.size).sum();

        ExtractionResult {
            image,
            extracted_count,
            total_size,
        }
    }

    fn magic_bytes(data: &[u8], offset: usize, magic: &[u8]) -> bool {
        if offset + magic.len() > data.len() {
            return false;
        }
        data[offset..offset + magic.len()] == *magic
    }

    pub fn detect_filesystems(data: &[u8]) -> Vec<String> {
        let mut fs = Vec::new();

        if Self::magic_bytes(data, 0, b"hsqs") {
            fs.push("SquashFS".to_string());
        }
        if data.len() > 4 {
            let u32_val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if u32_val == 0x20021985 || u32_val == 0x20031985 {
                fs.push("JFFS2".to_string());
            }
        }
        if Self::magic_bytes(data, 0, b"\x1f\x8b") {
            fs.push("gzip compressed".to_string());
        }
        if Self::magic_bytes(data, 0, b"BZh") {
            fs.push("bzip2 compressed".to_string());
        }
        if Self::magic_bytes(data, 0, b"\x89\x50\x4e\x47") {
            fs.push("PNG image (likely logo)".to_string());
        }
        if Self::magic_bytes(data, 0, b"\xff\xd8\xff") {
            fs.push("JPEG image".to_string());
        }
        if Self::magic_bytes(data, 1024, b"\xeb\x3c\x90") || Self::magic_bytes(data, 0, b"MZ") {
            fs.push("UBoot image".to_string());
        }
        if Self::magic_bytes(data, 0, b"\x7fELF") {
            fs.push("ELF binary".to_string());
        }
        if Self::magic_bytes(data, 0, b"#!/bin/sh") || Self::magic_bytes(data, 0, b"#!/bin/bash") {
            fs.push("Shell script".to_string());
        }
        if Self::magic_bytes(data, 0, b"PK\x03\x04") {
            fs.push("ZIP archive".to_string());
        }
        if Self::magic_bytes(data, 0, b"\x28\xb5\x2f\xfd") {
            fs.push("Zstandard compressed".to_string());
        }
        if Self::magic_bytes(data, 0, b"\x37\x7a\xbc\xaf\x27\x1c") {
            fs.push("7z archive".to_string());
        }
        if Self::magic_bytes(data, 0, b"\xfd\x37\x7a\x58\x5a\x00") {
            fs.push("XZ compressed".to_string());
        }
        if Self::magic_bytes(data, 257, b"ustar") {
            fs.push("tar archive".to_string());
        }
        if Self::magic_bytes(data, 0, b"CRA1") || Self::magic_bytes(data, 0, b"CRAM") {
            fs.push("CramFS".to_string());
        }
        if Self::magic_bytes(data, 0, b"\x1f\x9d") {
            fs.push("LZW compressed".to_string());
        }

        fs.sort();
        fs.dedup();
        fs
    }

    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] = freq[byte as usize].wrapping_add(1);
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in freq.iter() {
            if count == 0 {
                continue;
            }
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
        entropy
    }

    pub fn detect_sections(data: &[u8]) -> Vec<FirmwareSection> {
        let mut sections = Vec::new();
        let window = 4096;
        let step = 2048;

        if data.len() < window {
            let e = Self::calculate_entropy(data);
            sections.push(FirmwareSection {
                name: "whole".to_string(),
                offset: 0,
                size: data.len() as u64,
                entropy: e,
                section_type: if e > 7.5 { "encrypted/compressed" } else { "plain" }.to_string(),
            });
            return sections;
        }

        let mut pos = 0;
        let mut section_idx = 0usize;
        while pos + window <= data.len() {
            let chunk = &data[pos..pos + window];
            let e = Self::calculate_entropy(chunk);
            let stype = if e > 7.5 { "encrypted/compressed" } else if e > 6.0 {
                "semi-random"
            } else {
                "plain"
            };

            if let Some(last) = sections.last_mut() {
                if last.section_type == stype {
                    last.size += window as u64;
                } else {
                    sections.push(FirmwareSection {
                        name: format!("section_{}", section_idx),
                        offset: pos as u64,
                        size: window as u64,
                        entropy: e,
                        section_type: stype.to_string(),
                    });
                    section_idx += 1;
                }
            } else {
                sections.push(FirmwareSection {
                    name: format!("section_{}", section_idx),
                    offset: pos as u64,
                    size: window as u64,
                    entropy: e,
                    section_type: stype.to_string(),
                });
                section_idx += 1;
            }
            pos += step;
        }

        sections
    }

    fn candidate_files(_data: &[u8], _fs_types: &[String]) -> Vec<FirmwareFile> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty() {
        let result = FirmwareExtractor::analyze(&[], "empty.bin");
        assert_eq!(result.size, 0);
        assert!(result.detected_fs.is_empty());
    }

    #[test]
    fn test_detect_squashfs() {
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(b"hsqs");
        let fs = FirmwareExtractor::detect_filesystems(&data);
        assert!(fs.contains(&"SquashFS".to_string()));
    }

    #[test]
    fn test_detect_gzip() {
        let data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03hello";
        let fs = FirmwareExtractor::detect_filesystems(data);
        assert!(fs.contains(&"gzip compressed".to_string()));
    }

    #[test]
    fn test_detect_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let fs = FirmwareExtractor::detect_filesystems(data);
        assert!(fs.contains(&"ELF binary".to_string()));
    }

    #[test]
    fn test_calculate_entropy_uniform() {
        let data = vec![0x41u8; 1024];
        let e = FirmwareExtractor::calculate_entropy(&data);
        assert!(e < 0.1);
    }

    #[test]
    fn test_calculate_entropy_random() {
        let data: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let e = FirmwareExtractor::calculate_entropy(&data);
        assert!(e > 7.5);
    }

    #[test]
    fn test_detect_sections() {
        let data = vec![0x41u8; 8192];
        let sections = FirmwareExtractor::detect_sections(&data);
        assert!(!sections.is_empty());
        assert_eq!(sections[0].section_type, "plain");
    }

    #[test]
    fn test_entropy_high_compressed() {
        let mut data = Vec::new();
        for i in 0u8..=255 {
            for _ in 0..16 {
                data.push(i);
            }
        }
        let e = FirmwareExtractor::calculate_entropy(&data);
        assert!(e > 7.5);
    }

    #[test]
    fn test_image_struct() {
        let img = FirmwareImage {
            path: "test.bin".to_string(),
            size: 1024,
            detected_fs: vec!["SquashFS".to_string()],
            files: vec![],
            entropy: 4.5,
            sections: vec![],
        };
        let json = serde_json::to_string_pretty(&img).unwrap();
        assert!(json.contains("SquashFS"));
    }
}
