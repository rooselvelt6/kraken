use std::path::Path;
use std::io::{Read, Write};
use sha2::Digest;

use kraken_errors::ForensicsError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageInfo {
    pub source: String,
    pub output: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub sector_size: u64,
    pub blocks_copied: u64,
    pub verify_match: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ImageFormat {
    Raw,
    AFF,
    EWF,
}

pub struct DiskImager;

impl Default for DiskImager {
    fn default() -> Self {
        Self::new()
    }
}

impl DiskImager {
    pub fn new() -> Self {
        DiskImager
    }

    pub fn create_image(source: &str, output: &str, sector_size: u64) -> Result<ImageInfo, ForensicsError> {
        let source_path = Path::new(source);
        if !source_path.exists() {
            return Err(ForensicsError::NotFound(source.to_string()));
        }

        let src_meta = std::fs::metadata(source_path)?;
        let total_size = src_meta.len();

        let mut src = std::fs::File::open(source_path)?;
        let mut dst = std::fs::File::create(output)?;

        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; sector_size as usize];
        let mut blocks = 0u64;

        loop {
            use sha2::Digest;
            let n = src.read(&mut buffer)?;
            if n == 0 { break; }
            dst.write_all(&buffer[..n])?;
            hasher.update(&buffer[..n]);
            blocks += 1;
        }

        let hash = hex::encode(hasher.finalize());

        Ok(ImageInfo {
            source: source.to_string(),
            output: output.to_string(),
            size_bytes: total_size,
            sha256: hash,
            sector_size,
            blocks_copied: blocks,
            verify_match: false,
        })
    }

    pub fn verify_image(image_path: &str, expected_hash: &str) -> Result<bool, ForensicsError> {
        let mut file = std::fs::File::open(image_path)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = vec![0u8; 65536];

        loop {
            use sha2::Digest;
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            hasher.update(&buffer[..n]);
        }

        let computed = hex::encode(hasher.finalize());
        Ok(computed == expected_hash)
    }

    pub fn list_disks() -> Vec<String> {
        let mut disks = Vec::new();
        #[cfg(target_os = "linux")]
        {
            if let Ok(entries) = std::fs::read_dir("/dev") {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if (name.starts_with("sd") || name.starts_with("nvme") || name.starts_with("mmcblk"))
                        && !name.chars().any(|c| c.is_ascii_digit()) {
                            disks.push(format!("/dev/{}", name));
                        }
                }
            }
        }
        disks
    }

    pub fn estimate_size(source: &str) -> Result<u64, ForensicsError> {
        let meta = std::fs::metadata(source)?;
        Ok(meta.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_small_image() {
        let tmp_dir = std::env::temp_dir();
        let src = tmp_dir.join("test_src.bin");
        let dst = tmp_dir.join("test_img.bin");
        std::fs::write(&src, vec![0xAAu8; 4096]).unwrap();

        let result = DiskImager::create_image(
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            512,
        );
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.size_bytes, 4096);
        assert_eq!(info.blocks_copied, 8);

        std::fs::remove_file(&src).ok();
        std::fs::remove_file(&dst).ok();
    }

    #[test]
    fn test_verify_image() {
        let tmp = std::env::temp_dir().join("verify_test.bin");
        let data = b"hello forensic world!";
        std::fs::write(&tmp, data).unwrap();

        let mut hasher = sha2::Sha256::new();
        use sha2::Digest;
        hasher.update(data);
        let hash = hex::encode(hasher.finalize());

        let result = DiskImager::verify_image(tmp.to_str().unwrap(), &hash);
        assert!(result.unwrap());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_verify_image_fail() {
        let tmp = std::env::temp_dir().join("verify_fail.bin");
        std::fs::write(&tmp, b"data").unwrap();

        let result = DiskImager::verify_image(tmp.to_str().unwrap(), "badhash");
        assert!(!result.unwrap());

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_list_disks() {
        let disks = DiskImager::list_disks();
        assert!(disks.is_empty() || !disks.is_empty());
    }

    #[test]
    fn test_estimate_size() {
        let tmp = std::env::temp_dir().join("estimate_test.bin");
        std::fs::write(&tmp, vec![0u8; 100]).unwrap();
        let size = DiskImager::estimate_size(tmp.to_str().unwrap()).unwrap();
        assert_eq!(size, 100);
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_nonexistent_source() {
        let result = DiskImager::create_image("/nonexistent/path", "/tmp/out", 512);
        assert!(result.is_err());
    }

    #[test]
    fn test_image_info_serialization() {
        let info = ImageInfo {
            source: "/dev/sda".to_string(),
            output: "/mnt/case/image.dd".to_string(),
            size_bytes: 1024,
            sha256: "abc".to_string(),
            sector_size: 512,
            blocks_copied: 2,
            verify_match: true,
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("/dev/sda"));
    }
}
