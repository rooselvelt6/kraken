use goblin::pe::PE;
use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::Object;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub file_path: String,
    pub format: BinaryFormat,
    pub file_size: u64,
    pub entry_point: u64,
    pub is_64bit: bool,
    pub arch: String,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub symbols: Vec<String>,
    pub libraries: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub raw_offset: u64,
    pub permissions: String,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeDetails {
    pub subsystems: Vec<String>,
    pub compile_time: String,
    pub image_base: u64,
    pub dll_characteristics: Vec<String>,
    pub is_driver: bool,
    pub has_relocations: bool,
    pub has_tls: bool,
}

pub struct BinaryAnalyzer;

impl BinaryAnalyzer {
    pub fn analyze<P: AsRef<Path>>(path: P) -> Result<BinaryInfo, String> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| format!("Cannot read file: {}", e))?;

        let file_size = data.len() as u64;
        let file_path = path.as_ref().to_string_lossy().to_string();

        match Object::parse(&data).map_err(|e| format!("Parse error: {}", e))? {
            Object::Elf(elf) => Ok(Self::analyze_elf(&data, elf, &file_path, file_size)),
            Object::PE(pe) => Ok(Self::analyze_pe(&data, pe, &file_path, file_size)),
            Object::Mach(mach) => Ok(Self::analyze_mach(&data, mach, &file_path, file_size)),
            _ => Err("Unsupported binary format".to_string()),
        }
    }

    fn analyze_elf(data: &[u8], elf: Elf, file_path: &str, file_size: u64) -> BinaryInfo {
        let is_64 = elf.header.e_machine == goblin::elf::header::EM_X86_64
            || elf.header.e_machine == goblin::elf::header::EM_AARCH64;

        let arch = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64",
            goblin::elf::header::EM_386 => "x86",
            goblin::elf::header::EM_AARCH64 => "ARM64",
            goblin::elf::header::EM_ARM => "ARM",
            goblin::elf::header::EM_RISCV => "RISC-V",
            goblin::elf::header::EM_MIPS => "MIPS",
            _ => "unknown",
        }.to_string();

        let sections: Vec<SectionInfo> = elf.section_headers.iter().filter_map(|shdr| {
            let name = elf.shdr_strtab.get_at(shdr.sh_name).unwrap_or("unknown").to_string();
            if name.is_empty() { return None; }
            let flags = shdr.sh_flags as u64;
            let perms = format!("{}{}{}",
                if flags & goblin::elf::section_header::SHF_WRITE as u64 != 0 { "W" } else { "" },
                if flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0 { "A" } else { "" },
                if flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 { "X" } else { "" },
            );
            let raw_start = shdr.sh_offset as usize;
            let raw_end = (raw_start + shdr.sh_size as usize).min(data.len());
            let ent = if raw_end > raw_start {
                crate::entropy::compute_entropy(&data[raw_start..raw_end])
            } else {
                0.0
            };
            Some(SectionInfo {
                name,
                virtual_address: shdr.sh_addr,
                virtual_size: shdr.sh_size,
                raw_size: shdr.sh_size,
                raw_offset: shdr.sh_offset,
                permissions: perms,
                entropy: ent,
            })
        }).collect();

        let symbols: Vec<String> = elf.syms.iter()
            .filter_map(|s| elf.strtab.get_at(s.st_name))
            .map(|s| s.to_string())
            .collect();

        let imports: Vec<String> = elf.dynamic.as_ref().map(|dyn_info| {
            dyn_info.dyns.iter()
                .filter(|d| d.d_tag == goblin::elf::dynamic::DT_NEEDED)
                .filter_map(|d| {
                    elf.dynstrtab.get_at(d.d_val as usize)
                })
                .map(|s| s.to_string())
                .collect()
        }).unwrap_or_default();

        BinaryInfo {
            file_path: file_path.to_string(),
            format: BinaryFormat::Elf,
            file_size,
            entry_point: elf.entry,
            is_64bit: is_64,
            arch,
            sections,
            imports: imports.clone(),
            exports: Vec::new(),
            symbols,
            libraries: imports,
        }
    }

    fn analyze_pe(data: &[u8], pe: PE, file_path: &str, file_size: u64) -> BinaryInfo {
        let is_64 = pe.is_64;
        let arch = if is_64 { "x86_64" } else { "x86" }.to_string();

        let sections: Vec<SectionInfo> = pe.sections.iter().map(|s| {
            let name = s.name().unwrap_or("unknown").to_string();
            let perms = format!("{}{}{}",
                if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_WRITE != 0 { "W" } else { "" },
                if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0 { "X" } else { "" },
                if s.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_READ != 0 { "R" } else { "" },
            );
            let raw_start = s.pointer_to_raw_data as usize;
            let raw_end = (raw_start + s.size_of_raw_data as usize).min(data.len());
            let ent = if raw_end > raw_start {
                crate::entropy::compute_entropy(&data[raw_start..raw_end])
            } else {
                0.0
            };
            SectionInfo {
                name,
                virtual_address: s.virtual_address as u64,
                virtual_size: s.virtual_size as u64,
                raw_size: s.size_of_raw_data as u64,
                raw_offset: s.pointer_to_raw_data as u64,
                permissions: perms,
                entropy: ent,
            }
        }).collect();

        let mut imports = Vec::new();
        for import in &pe.imports {
            imports.push(import.dll.to_string());
        }

        let exports: Vec<String> = pe.exports.iter()
            .filter_map(|e| e.name.as_ref().map(|n| n.to_string()))
            .collect();

        BinaryInfo {
            file_path: file_path.to_string(),
            format: BinaryFormat::Pe,
            file_size,
            entry_point: pe.entry as u64,
            is_64bit: is_64,
            arch,
            sections,
            imports: imports.clone(),
            exports,
            symbols: Vec::new(),
            libraries: imports,
        }
    }

    fn analyze_mach(data: &[u8], mach: Mach, file_path: &str, file_size: u64) -> BinaryInfo {
        let (macho_data, is_64) = match mach {
            Mach::Binary(ref m) => {
                let is_64 = m.header.cputype() == goblin::mach::cputype::CPU_TYPE_X86_64
                    || m.header.cputype() == goblin::mach::cputype::CPU_TYPE_ARM64;
                (Some(m), is_64)
            }
            Mach::Fat(ref _fat) => {
                (None, false)
            }
        };

        let mach_o = match macho_data {
            Some(m) => m,
            None => {
                return BinaryInfo {
                    file_path: file_path.to_string(),
                    format: BinaryFormat::MachO,
                    file_size,
                    entry_point: 0,
                    is_64bit: false,
                    arch: "unknown".to_string(),
                    sections: Vec::new(),
                    imports: Vec::new(),
                    exports: Vec::new(),
                    symbols: Vec::new(),
                    libraries: Vec::new(),
                };
            }
        };

        let arch = match mach_o.header.cputype() {
            goblin::mach::cputype::CPU_TYPE_X86_64 => "x86_64",
            goblin::mach::cputype::CPU_TYPE_X86 => "x86",
            goblin::mach::cputype::CPU_TYPE_ARM64 => "ARM64",
            goblin::mach::cputype::CPU_TYPE_ARM => "ARM",
            _ => "unknown",
        }.to_string();

        let mut sections = Vec::new();
        for seg_iter in mach_o.segments.sections() {
            for item in seg_iter {
                if let Ok((sec, _data)) = item {
                let perms = format!("{}{}{}",
                    if sec.flags & 0x80000000 != 0 { "W" } else { "" },
                    if sec.flags & 0x00000004 != 0 { "X" } else { "" },
                    "R",
                );
                let raw_start = sec.offset as usize;
                let raw_end = (raw_start + sec.size as usize).min(data.len());
                let ent = if raw_end > raw_start {
                    crate::entropy::compute_entropy(&data[raw_start..raw_end])
                } else {
                    0.0
                };
                sections.push(SectionInfo {
                    name: String::from_utf8_lossy(&sec.sectname)
                        .trim_end_matches('\0')
                        .to_string(),
                    virtual_address: sec.addr,
                    virtual_size: sec.size,
                    raw_size: sec.size,
                    raw_offset: sec.offset as u64,
                    permissions: perms,
                    entropy: ent,
                });
            }
            }
        }

        let libraries: Vec<String> = mach_o.libs.iter()
            .map(|l| l.to_string())
            .collect();

        BinaryInfo {
            file_path: file_path.to_string(),
            format: BinaryFormat::MachO,
            file_size,
            entry_point: mach_o.entry,
            is_64bit: is_64,
            arch,
            sections,
            imports: libraries.clone(),
            exports: Vec::new(),
            symbols: Vec::new(),
            libraries,
        }
    }

    pub fn detect_format<P: AsRef<Path>>(path: P) -> Result<BinaryFormat, String> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| format!("Cannot read file: {}", e))?;

        if data.len() < 4 {
            return Err("File too small".to_string());
        }

        Ok(match &data[..4] {
            [0x7f, b'E', b'L', b'F'] => BinaryFormat::Elf,
            [0x4d, 0x5a, _, _] => BinaryFormat::Pe,
            [0xfe, 0xed, 0xfa, _] | [0xce, 0xfa, 0xed, _] | [0xca, 0xfe, 0xba, 0xbe] | [0xbe, 0xba, 0xfe, 0xca] => BinaryFormat::MachO,
            _ => {
                if data.len() > 2 && data[0] == 0x4d && data[1] == 0x5a {
                    BinaryFormat::Pe
                } else {
                    BinaryFormat::Unknown
                }
            }
        })
    }

    pub fn section_map<P: AsRef<Path>>(path: P) -> Result<Vec<(String, Vec<u8>)>, String> {
        let bin = Self::analyze(path.as_ref())?;
        let data = std::fs::read(path.as_ref())
            .map_err(|e| format!("Cannot read: {}", e))?;

        let mut result = Vec::new();
        for section in &bin.sections {
            let start = section.raw_offset as usize;
            let end = (start + section.raw_size as usize).min(data.len());
            if end > start {
                result.push((section.name.clone(), data[start..end].to_vec()));
            }
        }
        Ok(result)
    }
}

pub fn format_binary_info(info: &BinaryInfo) -> String {
    let mut out = format!("Binary Analysis: {}\n", info.file_path);
    out.push_str(&format!("Format: {:?}\n", info.format));
    out.push_str(&format!("Arch: {} ({})\n", info.arch, if info.is_64bit { "64-bit" } else { "32-bit" }));
    out.push_str(&format!("Entry Point: {:#x}\n", info.entry_point));
    out.push_str(&format!("File Size: {} bytes\n", info.file_size));

    if !info.sections.is_empty() {
        out.push_str(&format!("\nSections ({}):\n", info.sections.len()));
        for sec in &info.sections {
            out.push_str(&format!("  {:<12} VA={:#010x} size={:<8} perms={:<4} entropy={:.3}\n",
                sec.name, sec.virtual_address, sec.raw_size, sec.permissions, sec.entropy));
        }
    }

    if !info.imports.is_empty() {
        out.push_str(&format!("\nImports ({}):\n", info.imports.len()));
        for imp in &info.imports {
            out.push_str(&format!("  {}\n", imp));
        }
    }

    if !info.exports.is_empty() {
        out.push_str(&format!("\nExports ({}):\n", info.exports.len()));
        for exp in &info.exports {
            out.push_str(&format!("  {}\n", exp));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_format_elf() {
        let elf_data = [0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        let path = "/tmp/test_elf_detect.bin";
        std::fs::write(path, &elf_data).ok();
        let format = BinaryAnalyzer::detect_format(path);
        assert!(format.is_ok());
        assert!(matches!(format.unwrap(), BinaryFormat::Elf));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_detect_format_pe() {
        let pe_data = [0x4d, 0x5a, 0x90, 0x00];
        let path = "/tmp/test_pe_detect.bin";
        std::fs::write(path, &pe_data).ok();
        let format = BinaryAnalyzer::detect_format(path);
        assert!(format.is_ok());
        assert!(matches!(format.unwrap(), BinaryFormat::Pe));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_detect_format_unknown() {
        let data = b"not a binary file at all";
        let path = "/tmp/test_unknown_detect.bin";
        std::fs::write(path, data).ok();
        let format = BinaryAnalyzer::detect_format(path);
        assert!(matches!(format.unwrap(), BinaryFormat::Unknown));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_section_info_defaults() {
        let info = SectionInfo {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 1024,
            raw_size: 512,
            raw_offset: 0x200,
            permissions: "RX".to_string(),
            entropy: 4.5,
        };
        assert_eq!(info.name, ".text");
        assert!(info.permissions.contains("R"));
        assert!(info.permissions.contains("X"));
    }

    #[test]
    fn test_binary_info_display() {
        let info = BinaryInfo {
            file_path: "/bin/ls".to_string(),
            format: BinaryFormat::Elf,
            file_size: 100000,
            entry_point: 0x4000,
            is_64bit: true,
            arch: "x86_64".to_string(),
            sections: vec![],
            imports: vec!["libc.so.6".to_string()],
            exports: vec![],
            symbols: vec![],
            libraries: vec![],
        };
        let formatted = format_binary_info(&info);
        assert!(formatted.contains("Elf"));
        assert!(formatted.contains("x86_64"));
        assert!(formatted.contains("libc.so.6"));
    }

    #[test]
    fn test_nonexistent_file() {
        let result = BinaryAnalyzer::analyze("/tmp/nonexistent_binary.elf");
        assert!(result.is_err());
    }

    #[test]
    fn test_format_types() {
        assert!(matches!(BinaryFormat::Elf, BinaryFormat::Elf));
        assert!(matches!(BinaryFormat::Pe, BinaryFormat::Pe));
        assert!(matches!(BinaryFormat::MachO, BinaryFormat::MachO));
    }
}
