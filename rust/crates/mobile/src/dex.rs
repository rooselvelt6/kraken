use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexFile {
    pub header: DexHeader,
    pub class_defs: Vec<ClassDef>,
    pub method_defs: Vec<MethodDef>,
    pub field_defs: Vec<FieldDef>,
    pub proto_defs: Vec<ProtoDef>,
    pub string_pool: Vec<String>,
    pub type_pool: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexHeader {
    pub magic: String,
    pub checksum: u32,
    pub signature: String,
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_offset: u32,
    pub map_offset: u32,
    pub string_ids_size: u32,
    pub string_ids_offset: u32,
    pub type_ids_size: u32,
    pub type_ids_offset: u32,
    pub proto_ids_size: u32,
    pub proto_ids_offset: u32,
    pub field_ids_size: u32,
    pub field_ids_offset: u32,
    pub method_ids_size: u32,
    pub method_ids_offset: u32,
    pub class_defs_size: u32,
    pub class_defs_offset: u32,
    pub data_size: u32,
    pub data_offset: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassDef {
    pub class_id: u32,
    pub access_flags: u32,
    pub superclass_id: u32,
    pub interfaces_offset: u32,
    pub source_file_id: u32,
    pub annotations_offset: u32,
    pub class_data_offset: u32,
    pub static_values_offset: u32,
    pub class_name: String,
    pub superclass_name: String,
    pub interfaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDef {
    pub class_name: String,
    pub name: String,
    pub prototype: String,
    pub access_flags: u32,
    pub code_offset: u32,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub offset: u32,
    pub opcode: u16,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub class_name: String,
    pub name: String,
    pub field_type: String,
    pub access_flags: u32,
    pub static_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoDef {
    pub shorty: String,
    pub return_type: String,
    pub parameter_types: Vec<String>,
}

pub struct DexParser;

impl Default for DexParser {
    fn default() -> Self {
        DexParser
    }
}

impl DexParser {
    pub fn new() -> Self {
        DexParser
    }

    pub fn parse(data: &[u8]) -> Result<DexFile, String> {
        if data.len() < 40 {
            return Err("File too small for DEX header".to_string());
        }

        if &data[0..4] != b"dex\n" {
            return Err("Invalid DEX magic: missing 'dex\\n'".to_string());
        }

        let header = Self::parse_header(data)?;
        let string_pool = Self::parse_string_pool(data, &header);
        let type_pool = Self::parse_type_pool(data, &header, &string_pool);
        let proto_defs = Self::parse_proto_defs(data, &header, &string_pool, &type_pool);
        let field_defs = Self::parse_field_defs(data, &header, &string_pool, &type_pool);
        let method_defs = Self::parse_method_defs(data, &header, &string_pool, &type_pool, &proto_defs);
        let class_defs = Self::parse_class_defs(data, &header, &string_pool, &type_pool);

        Ok(DexFile {
            header,
            class_defs,
            method_defs,
            field_defs,
            proto_defs,
            string_pool,
            type_pool,
        })
    }

    fn parse_header(data: &[u8]) -> Result<DexHeader, String> {
        let read_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };

        Ok(DexHeader {
            magic: format!("{:02x} {:02x} {:02x} {:02x}", data[0], data[1], data[2], data[3]),
            checksum: read_u32(8),
            signature: hex::encode(&data[12..20]),
            file_size: read_u32(32),
            header_size: read_u32(36),
            endian_tag: read_u32(40),
            link_size: read_u32(44),
            link_offset: read_u32(48),
            map_offset: read_u32(52),
            string_ids_size: read_u32(56),
            string_ids_offset: read_u32(60),
            type_ids_size: read_u32(64),
            type_ids_offset: read_u32(68),
            proto_ids_size: read_u32(72),
            proto_ids_offset: read_u32(76),
            field_ids_size: read_u32(80),
            field_ids_offset: read_u32(84),
            method_ids_size: read_u32(88),
            method_ids_offset: read_u32(92),
            class_defs_size: read_u32(96),
            class_defs_offset: read_u32(100),
            data_size: read_u32(104),
            data_offset: read_u32(108),
        })
    }

    fn read_uleb128(data: &[u8], offset: &mut usize) -> u32 {
        let mut result = 0u32;
        let mut shift = 0;
        loop {
            let byte = data.get(*offset).copied().unwrap_or(0);
            *offset += 1;
            result |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        result
    }

    fn parse_string_pool(data: &[u8], header: &DexHeader) -> Vec<String> {
        let mut strings = Vec::new();
        if header.string_ids_size == 0 {
            return strings;
        }
        for i in 0..header.string_ids_size as usize {
            let off = header.string_ids_offset as usize + i * 4;
            if off + 4 > data.len() {
                break;
            }
            let str_off = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            if str_off >= data.len() {
                strings.push(format!("<invalid_string_{}>", i));
                continue;
            }
            let mut pos = str_off;
            let _size = Self::read_uleb128(data, &mut pos);
            let mut s = Vec::new();
            while pos < data.len() && data[pos] != 0 {
                s.push(data[pos]);
                pos += 1;
            }
            strings.push(String::from_utf8_lossy(&s).to_string());
        }
        strings
    }

    fn parse_type_pool(data: &[u8], header: &DexHeader, strings: &[String]) -> Vec<String> {
        let mut types = Vec::new();
        for i in 0..header.type_ids_size as usize {
            let off = header.type_ids_offset as usize + i * 4;
            if off + 4 > data.len() {
                break;
            }
            let idx = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let name = strings.get(idx).cloned().unwrap_or_else(|| format!("<type_{}>", i));
            types.push(name);
        }
        types
    }

    fn parse_proto_defs(data: &[u8], header: &DexHeader, strings: &[String], _types: &[String]) -> Vec<ProtoDef> {
        let mut protos = Vec::new();
        for i in 0..header.proto_ids_size as usize {
            let off = header.proto_ids_offset as usize + i * 12;
            if off + 12 > data.len() {
                break;
            }
            let shorty_idx = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let return_type_idx = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
            let params_offset = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as usize;

            let shorty = strings.get(shorty_idx).cloned().unwrap_or_default();
            let return_type = strings.get(return_type_idx).cloned().unwrap_or_default();
            let param_types = if params_offset > 0 && params_offset + 4 <= data.len() {
                let param_count = u32::from_le_bytes(data[params_offset..params_offset + 4].try_into().unwrap()) as usize;
                let mut params = Vec::new();
                for j in 0..param_count {
                    let idx = params_offset + 4 + j * 4;
                    if idx + 4 > data.len() {
                        break;
                    }
                    let type_idx = u32::from_le_bytes(data[idx..idx + 4].try_into().unwrap()) as usize;
                    params.push(_types.get(type_idx).cloned().unwrap_or_default());
                }
                params
            } else {
                Vec::new()
            };

            protos.push(ProtoDef { shorty, return_type, parameter_types: param_types });
        }
        protos
    }

    fn parse_field_defs(data: &[u8], header: &DexHeader, strings: &[String], _types: &[String]) -> Vec<FieldDef> {
        let mut fields = Vec::new();
        for i in 0..header.field_ids_size as usize {
            let off = header.field_ids_offset as usize + i * 8;
            if off + 8 > data.len() {
                break;
            }
            let class_idx = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
            let type_idx = u16::from_le_bytes(data[off + 2..off + 4].try_into().unwrap()) as usize;
            let name_idx = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;

            let class_name = _types.get(class_idx).cloned().unwrap_or_default();
            let field_type = _types.get(type_idx).cloned().unwrap_or_default();
            let name = strings.get(name_idx).cloned().unwrap_or_default();

            fields.push(FieldDef {
                class_name,
                name,
                field_type,
                access_flags: 0,
                static_value: None,
            });
        }
        fields
    }

    fn parse_method_defs(data: &[u8], header: &DexHeader, strings: &[String], _types: &[String], protos: &[ProtoDef]) -> Vec<MethodDef> {
        let mut methods = Vec::new();
        for i in 0..header.method_ids_size as usize {
            let off = header.method_ids_offset as usize + i * 8;
            if off + 8 > data.len() {
                break;
            }
            let class_idx = u16::from_le_bytes(data[off..off + 2].try_into().unwrap()) as usize;
            let proto_idx = u16::from_le_bytes(data[off + 2..off + 4].try_into().unwrap()) as usize;
            let name_idx = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;

            let class_name = _types.get(class_idx).cloned().unwrap_or_default();
            let name = strings.get(name_idx).cloned().unwrap_or_default();
            let proto = protos.get(proto_idx).map(|p| format!("({}){}", p.parameter_types.join(", "), p.return_type)).unwrap_or_default();

            methods.push(MethodDef {
                class_name,
                name,
                prototype: proto,
                access_flags: 0,
                code_offset: 0,
                instructions: Vec::new(),
            });
        }
        methods
    }

    fn parse_class_defs(data: &[u8], header: &DexHeader, _strings: &[String], _types: &[String]) -> Vec<ClassDef> {
        let mut classes = Vec::new();
        for i in 0..header.class_defs_size as usize {
            let off = header.class_defs_offset as usize + i * 32;
            if off + 32 > data.len() {
                break;
            }
            let class_id = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            let access_flags = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
            let superclass_id = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
            let interfaces_offset = u32::from_le_bytes(data[off + 12..off + 16].try_into().unwrap());
            let source_file_id = u32::from_le_bytes(data[off + 28..off + 32].try_into().unwrap());

            let class_name = _types.get(class_id as usize).cloned().unwrap_or_default();
            let superclass_name = _types.get(superclass_id as usize).cloned().unwrap_or_default();

            let mut interfaces = Vec::new();
            if interfaces_offset > 0 && interfaces_offset as usize + 4 <= data.len() {
                let count = u32::from_le_bytes(data[interfaces_offset as usize..interfaces_offset as usize + 4].try_into().unwrap()) as usize;
                for j in 0..count {
                    let idx = interfaces_offset as usize + 4 + j * 4;
                    if idx + 4 > data.len() { break; }
                    let type_idx = u32::from_le_bytes(data[idx..idx + 4].try_into().unwrap()) as usize;
                    interfaces.push(_types.get(type_idx).cloned().unwrap_or_default());
                }
            }

            classes.push(ClassDef {
                class_id,
                access_flags,
                superclass_id,
                interfaces_offset,
                source_file_id,
                annotations_offset: 0,
                class_data_offset: 0,
                static_values_offset: 0,
                class_name,
                superclass_name,
                interfaces,
            });
        }
        classes
    }

    pub fn find_string(data: &[u8], target: &str) -> Vec<u32> {
        let mut offsets = Vec::new();
        let target_bytes = target.as_bytes();
        let mut pos = 0usize;
        while let Some(start) = data[pos..].windows(target_bytes.len()).position(|w| w == target_bytes) {
            let abs = pos + start;
            offsets.push(abs as u32);
            pos = abs + 1;
        }
        offsets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_dex() -> Vec<u8> {
        let mut dex = vec![0u8; 256];
        dex[0..4].copy_from_slice(b"dex\n");
        dex[4..8].copy_from_slice(&[0x35, 0x00, 0x00, 0x00]);
        dex[8..12].copy_from_slice(&0x12345678u32.to_le_bytes());
        dex[12..32].fill(0);
        dex[32..36].copy_from_slice(&256u32.to_le_bytes());
        dex[36..40].copy_from_slice(&112u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        dex
    }

    #[test]
    fn test_parse_invalid() {
        let result = DexParser::parse(b"bad");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_valid() {
        let data = create_test_dex();
        let result = DexParser::parse(&data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_header() {
        let data = create_test_dex();
        let dex = DexParser::parse(&data).unwrap();
        assert_eq!(dex.header.file_size, 256);
        assert!(dex.header.magic.starts_with("64"));
    }

    #[test]
    fn test_find_string() {
        let data = b"hello dex world";
        let offsets = DexParser::find_string(data, "dex");
        assert_eq!(offsets.len(), 1);
        assert_eq!(offsets[0], 6);
    }

    #[test]
    fn test_find_string_not_found() {
        let offsets = DexParser::find_string(b"hello", "dex");
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_dex_file_serde() {
        let dex = DexFile {
            header: DexHeader {
                magic: "dex".to_string(),
                checksum: 0,
                signature: "".to_string(),
                file_size: 0,
                header_size: 0,
                endian_tag: 0,
                link_size: 0,
                link_offset: 0,
                map_offset: 0,
                string_ids_size: 0,
                string_ids_offset: 0,
                type_ids_size: 0,
                type_ids_offset: 0,
                proto_ids_size: 0,
                proto_ids_offset: 0,
                field_ids_size: 0,
                field_ids_offset: 0,
                method_ids_size: 0,
                method_ids_offset: 0,
                class_defs_size: 0,
                class_defs_offset: 0,
                data_size: 0,
                data_offset: 0,
            },
            class_defs: vec![],
            method_defs: vec![],
            field_defs: vec![],
            proto_defs: vec![],
            string_pool: vec![],
            type_pool: vec![],
        };
        let json = serde_json::to_string_pretty(&dex).unwrap();
        assert!(json.contains("dex"));
    }
}
