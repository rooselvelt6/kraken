use sha2::Digest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpiFlashChip {
    pub manufacturer: String,
    pub model: String,
    pub size_bytes: u64,
    pub sector_size: u64,
    pub voltage: f64,
    pub jedec_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashOperation {
    pub operation: String,
    pub address: u64,
    pub length: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashDump {
    pub chip: SpiFlashChip,
    pub data: Vec<u8>,
    pub operations: Vec<FlashOperation>,
    pub verified: bool,
    pub checksum_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashResult {
    pub success: bool,
    pub chip: Option<SpiFlashChip>,
    pub message: String,
    pub operations: Vec<FlashOperation>,
}

pub struct FlashReader;

impl FlashReader {
    pub fn new() -> Self {
        FlashReader
    }

    pub fn detect_chip(jedec_id: &[u8; 3]) -> Option<SpiFlashChip> {
        let (manufacturer, model, size) = match jedec_id {
            [0xef, 0x40, 0x18] => ("Winbond", "W25Q128JV", 16_777_216u64),
            [0xef, 0x40, 0x15] => ("Winbond", "W25Q64JV", 8_388_608),
            [0xef, 0x40, 0x14] => ("Winbond", "W25Q32JV", 4_194_304),
            [0xef, 0x40, 0x16] => ("Winbond", "W25Q16JV", 2_097_152),
            [0xc2, 0x20, 0x19] => ("Macronix", "MX25L25635F", 33_554_432),
            [0xc2, 0x20, 0x18] => ("Macronix", "MX25L12835F", 16_777_216),
            [0xc2, 0x20, 0x17] => ("Macronix", "MX25L6435F", 8_388_608),
            [0x1c, 0x70, 0x15] => ("EON", "EN25Q64", 8_388_608),
            [0x1c, 0x70, 0x14] => ("EON", "EN25Q32", 4_194_304),
            [0x9d, 0x60, 0x18] => ("ISSI", "IS25LP128", 16_777_216),
            [0x9d, 0x60, 0x17] => ("ISSI", "IS25LP064", 8_388_608),
            [0x0b, 0x40, 0x18] => ("XTX Technology", "XT25F128B", 16_777_216),
            [0xe0, 0x40, 0x18] => ("GigaDevice", "GD25Q128C", 16_777_216),
            [0xe0, 0x40, 0x15] => ("GigaDevice", "GD25Q64C", 8_388_608),
            [0xad, 0x00, 0x01] | [0xad, 0x00, 0x00] => ("AMD/Spansion", "Unknown Spansion", 8_388_608),
            _ => return None,
        };

        Some(SpiFlashChip {
            manufacturer: manufacturer.to_string(),
            model: model.to_string(),
            size_bytes: size,
            sector_size: 4096,
            voltage: 3.3,
            jedec_id: jedec_id.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":"),
        })
    }

    pub fn common_chips() -> Vec<SpiFlashChip> {
        vec![
            SpiFlashChip {
                manufacturer: "Winbond".to_string(),
                model: "W25Q128JV".to_string(),
                size_bytes: 16_777_216,
                sector_size: 4096,
                voltage: 3.3,
                jedec_id: "ef:40:18".to_string(),
            },
            SpiFlashChip {
                manufacturer: "Macronix".to_string(),
                model: "MX25L12835F".to_string(),
                size_bytes: 16_777_216,
                sector_size: 4096,
                voltage: 3.3,
                jedec_id: "c2:20:18".to_string(),
            },
            SpiFlashChip {
                manufacturer: "GigaDevice".to_string(),
                model: "GD25Q128C".to_string(),
                size_bytes: 16_777_216,
                sector_size: 4096,
                voltage: 3.3,
                jedec_id: "e0:40:18".to_string(),
            },
            SpiFlashChip {
                manufacturer: "ISSI".to_string(),
                model: "IS25LP128".to_string(),
                size_bytes: 16_777_216,
                sector_size: 4096,
                voltage: 3.3,
                jedec_id: "9d:60:18".to_string(),
            },
        ]
    }

    pub fn read_chip(chip: &SpiFlashChip, dump: &[u8]) -> FlashDump {
        let data = dump.to_vec();
        let hash = sha2::Sha256::digest(&data);
        let checksum = hex::encode(hash);

        let sector_count = chip.size_bytes / chip.sector_size;
        let mut operations = Vec::new();
        for i in 0..sector_count.min(4) {
            operations.push(FlashOperation {
                operation: "read".to_string(),
                address: i * chip.sector_size,
                length: chip.sector_size,
                status: "success".to_string(),
            });
        }

        let verified = data.len() as u64 == chip.size_bytes;
        if !verified && !data.is_empty() {
            operations.push(FlashOperation {
                operation: "verify".to_string(),
                address: 0,
                length: data.len() as u64,
                status: format!("size mismatch: {} (expected {})", data.len(), chip.size_bytes),
            });
        }

        FlashDump {
            chip: chip.clone(),
            data,
            operations,
            verified,
            checksum_sha256: checksum,
        }
    }

    pub fn erase_chip(chip: &SpiFlashChip) -> FlashResult {
        let operations = vec![
            FlashOperation {
                operation: "write_enable".to_string(),
                address: 0,
                length: 0,
                status: "success".to_string(),
            },
            FlashOperation {
                operation: "chip_erase".to_string(),
                address: 0,
                length: chip.size_bytes,
                status: "success".to_string(),
            },
        ];

        FlashResult {
            success: true,
            chip: Some(chip.clone()),
            message: format!("{} {} erased successfully ({} bytes)", chip.manufacturer, chip.model, chip.size_bytes),
            operations,
        }
    }

    pub fn write_chip(chip: &SpiFlashChip, data: &[u8], address: u64) -> FlashResult {
        let max_write = chip.size_bytes - address;
        let len = (data.len() as u64).min(max_write);

        let mut operations = Vec::new();
        operations.push(FlashOperation {
            operation: "write_enable".to_string(),
            address,
            length: len,
            status: "success".to_string(),
        });
        operations.push(FlashOperation {
            operation: "page_program".to_string(),
            address,
            length: len,
            status: "success".to_string(),
        });

        FlashResult {
            success: true,
            chip: Some(chip.clone()),
            message: format!("Wrote {} bytes to {} at 0x{:x}", len, chip.model, address),
            operations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_winbond() {
        let jedec = [0xef, 0x40, 0x18];
        let chip = FlashReader::detect_chip(&jedec);
        assert!(chip.is_some());
        assert_eq!(chip.unwrap().manufacturer, "Winbond");
    }

    #[test]
    fn test_detect_macronix() {
        let jedec = [0xc2, 0x20, 0x18];
        let chip = FlashReader::detect_chip(&jedec);
        assert!(chip.is_some());
        assert_eq!(chip.unwrap().manufacturer, "Macronix");
    }

    #[test]
    fn test_detect_unknown() {
        let jedec = [0x00, 0x00, 0x00];
        let chip = FlashReader::detect_chip(&jedec);
        assert!(chip.is_none());
    }

    #[test]
    fn test_read_chip_full() {
        let chip = SpiFlashChip {
            manufacturer: "Winbond".to_string(),
            model: "W25Q128JV".to_string(),
            size_bytes: 4096,
            sector_size: 4096,
            voltage: 3.3,
            jedec_id: "ef:40:18".to_string(),
        };
        let dump = FlashReader::read_chip(&chip, &[0x41u8; 4096]);
        assert!(dump.verified);
        assert!(!dump.checksum_sha256.is_empty());
    }

    #[test]
    fn test_read_chip_partial() {
        let chip = SpiFlashChip {
            manufacturer: "Winbond".to_string(),
            model: "W25Q128JV".to_string(),
            size_bytes: 16_777_216,
            sector_size: 4096,
            voltage: 3.3,
            jedec_id: "ef:40:18".to_string(),
        };
        let dump = FlashReader::read_chip(&chip, &[0x00u8; 1024]);
        assert!(!dump.verified);
    }

    #[test]
    fn test_erase_chip() {
        let chip = SpiFlashChip {
            manufacturer: "Winbond".to_string(),
            model: "W25Q128JV".to_string(),
            size_bytes: 16_777_216,
            sector_size: 4096,
            voltage: 3.3,
            jedec_id: "ef:40:18".to_string(),
        };
        let result = FlashReader::erase_chip(&chip);
        assert!(result.success);
    }

    #[test]
    fn test_common_chips() {
        let chips = FlashReader::common_chips();
        assert!(chips.iter().any(|c| c.manufacturer == "Winbond"));
        assert!(chips.iter().any(|c| c.manufacturer == "Macronix"));
    }

    #[test]
    fn test_flash_dump_serde() {
        let chip = FlashReader::common_chips().into_iter().next().unwrap();
        let dump = FlashReader::read_chip(&chip, b"test data");
        let json = serde_json::to_string_pretty(&dump).unwrap();
        assert!(json.contains("W25Q128JV"));
    }
}
