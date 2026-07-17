use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CarvedFile {
    pub file_type: String,
    pub offset: u64,
    pub size: u64,
    pub output_path: String,
    pub signature_hex: String,
    pub extension: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CarvingResult {
    pub files: Vec<CarvedFile>,
    pub total_scanned: u64,
    pub total_carved: usize,
}

pub struct FileCarver {
    signatures: Vec<FileSignature>,
    chunk_size: usize,
}

struct FileSignature {
    name: &'static str,
    extension: &'static str,
    header: Vec<u8>,
    footer: Option<Vec<u8>>,
    min_size: u64,
    max_size: u64,
}

impl Default for FileCarver {
    fn default() -> Self {
        Self::new()
    }
}

impl FileCarver {
    pub fn new() -> Self {
        FileCarver {
            signatures: Self::default_signatures(),
            chunk_size: 4_194_304,
        }
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    fn default_signatures() -> Vec<FileSignature> {
        vec![
            FileSignature { name: "JPEG", extension: "jpg", header: vec![0xFF, 0xD8, 0xFF], footer: Some(vec![0xFF, 0xD9]), min_size: 100, max_size: 50_000_000 },
            FileSignature { name: "PNG", extension: "png", header: vec![0x89, 0x50, 0x4E, 0x47], footer: Some(vec![0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]), min_size: 100, max_size: 50_000_000 },
            FileSignature { name: "PDF", extension: "pdf", header: vec![0x25, 0x50, 0x44, 0x46], footer: None, min_size: 100, max_size: 100_000_000 },
            FileSignature { name: "ZIP", extension: "zip", header: vec![0x50, 0x4B, 0x03, 0x04], footer: None, min_size: 100, max_size: 200_000_000 },
            FileSignature { name: "RAR", extension: "rar", header: vec![0x52, 0x61, 0x72, 0x21], footer: None, min_size: 100, max_size: 200_000_000 },
            FileSignature { name: "GIF", extension: "gif", header: vec![0x47, 0x49, 0x46, 0x38], footer: Some(vec![0x00, 0x3B]), min_size: 100, max_size: 10_000_000 },
            FileSignature { name: "ELF", extension: "elf", header: vec![0x7F, 0x45, 0x4C, 0x46], footer: None, min_size: 100, max_size: 100_000_000 },
            FileSignature { name: "PE", extension: "exe", header: vec![0x4D, 0x5A], footer: None, min_size: 1000, max_size: 200_000_000 },
            FileSignature { name: "MP4", extension: "mp4", header: vec![0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70], footer: None, min_size: 1000, max_size: 500_000_000 },
            FileSignature { name: "DOCX", extension: "docx", header: vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00], footer: None, min_size: 1000, max_size: 50_000_000 },
            FileSignature { name: "BMP", extension: "bmp", header: vec![0x42, 0x4D], footer: None, min_size: 100, max_size: 50_000_000 },
            FileSignature { name: "RIFF", extension: "avi", header: vec![0x52, 0x49, 0x46, 0x46], footer: None, min_size: 1000, max_size: 500_000_000 },
            FileSignature { name: "MZ_EXE", extension: "exe", header: vec![0x4D, 0x5A, 0x90, 0x00], footer: None, min_size: 1000, max_size: 200_000_000 },
        ]
    }

    pub fn carve_file(&self, data: &[u8], output_dir: &str) -> CarvingResult {
        let mut files = Vec::new();
        let total_scanned = data.len() as u64;

        for sig in &self.signatures {
            let mut offset = 0;
            while offset < data.len() {
                if offset + sig.header.len() > data.len() { break; }
                if data[offset..offset + sig.header.len()] == sig.header {
                    let start = offset as u64;

                    let end = if let Some(ref footer) = sig.footer {
                        if let Some(footer_pos) = Self::find_footer(data, offset, footer) {
                            footer_pos as u64 + footer.len() as u64
                        } else {
                            (data.len().min(offset + sig.max_size as usize)) as u64
                        }
                    } else {
                        (data.len().min(offset + sig.max_size as usize)) as u64
                    };

                    let size = end - start;
                    if size >= sig.min_size && size <= sig.max_size {
                        let filename = format!("{}_{}_{}.{}", sig.name, start, size, sig.extension);
                        let out_path = Path::new(output_dir).join(&filename);
                        if let Ok(mut f) = std::fs::File::create(&out_path) {
                            use std::io::Write;
                            let _ = f.write_all(&data[start as usize..end as usize]);
                        }

                        files.push(CarvedFile {
                            file_type: sig.name.to_string(),
                            offset: start,
                            size,
                            output_path: out_path.to_string_lossy().to_string(),
                            signature_hex: hex::encode(&sig.header),
                            extension: sig.extension.to_string(),
                        });
                    }

                    offset += if size > 0 { size as usize } else { sig.header.len() };
                } else {
                    offset += 1;
                }
            }
        }

        CarvingResult {
            total_carved: files.len(),
            total_scanned,
            files,
        }
    }

    fn find_footer(data: &[u8], start: usize, footer: &[u8]) -> Option<usize> {
        let max_search = data.len().min(start + 10_000_000);
        let search_start = start + 1;
        if search_start >= data.len() { return None; }
        data[search_start..max_search]
            .windows(footer.len())
            .position(|w| w == footer)
            .map(|pos| search_start + pos)
    }

    pub fn carve_file_from_path(&self, path: &str, output_dir: &str) -> Result<CarvingResult, String> {
        let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;
        Ok(self.carve_file(&data, output_dir))
    }

    pub fn deep_scan(&self, path: &str, output_dir: &str) -> Result<CarvingResult, String> {
        let path = Path::new(path);
        if !path.exists() {
            return Err("Path does not exist".to_string());
        }

        let mut all_files = Vec::new();
        let mut total_scanned = 0u64;

        if path.is_dir() {
            let walker = walkdir::WalkDir::new(path).follow_links(false);
            for entry in walker.into_iter().flatten() {
                if entry.file_type().is_file() {
                    if let Ok(data) = std::fs::read(entry.path()) {
                        total_scanned += data.len() as u64;
                        let result = self.carve_file(&data, output_dir);
                        all_files.extend(result.files);
                    }
                }
            }
        } else {
            let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;
            total_scanned = data.len() as u64;
            let result = self.carve_file(&data, output_dir);
            all_files = result.files;
        }

        Ok(CarvingResult {
            total_carved: all_files.len(),
            total_scanned,
            files: all_files,
        })
    }

    pub fn add_custom_signature(&mut self, name: &'static str, extension: &'static str, header: Vec<u8>) {
        self.signatures.push(FileSignature {
            name,
            extension,
            header,
            footer: None,
            min_size: 10,
            max_size: 100_000_000,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_jpeg() {
        let carver = FileCarver::new();
        let mut data = vec![0u8; 10000];
        data[0..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
        data[500..502].copy_from_slice(&[0xFF, 0xD9]);

        let tmp = std::env::temp_dir().join("carve_test");
        std::fs::create_dir_all(&tmp).unwrap();
        let result = carver.carve_file(&data, tmp.to_str().unwrap());
        assert_eq!(result.total_carved, 1);
        assert_eq!(result.files[0].file_type, "JPEG");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_carve_png() {
        let carver = FileCarver::new();
        let mut data = vec![0u8; 1000];
        data[0..4].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47]);
        data[900..908].copy_from_slice(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);

        let tmp = std::env::temp_dir().join("carve_png");
        std::fs::create_dir_all(&tmp).unwrap();
        let result = carver.carve_file(&data, tmp.to_str().unwrap());
        assert_eq!(result.total_carved, 1);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_carve_pdf() {
        let carver = FileCarver::new();
        let mut data = vec![0u8; 500];
        data[0..4].copy_from_slice(&[0x25, 0x50, 0x44, 0x46]);

        let tmp = std::env::temp_dir().join("carve_pdf");
        std::fs::create_dir_all(&tmp).unwrap();
        let result = carver.carve_file(&data, tmp.to_str().unwrap());
        assert_eq!(result.total_carved, 1);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_carve_too_small() {
        let carver = FileCarver::new();
        let mut data = vec![0u8; 50];
        data[0..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);

        let tmp = std::env::temp_dir().join("carve_small");
        std::fs::create_dir_all(&tmp).unwrap();
        let result = carver.carve_file(&data, tmp.to_str().unwrap());
        assert_eq!(result.total_carved, 0);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_carve_result_serialization() {
        let result = CarvingResult {
            files: vec![CarvedFile {
                file_type: "JPEG".to_string(),
                offset: 0,
                size: 100,
                output_path: "/tmp/out.jpg".to_string(),
                signature_hex: "ffd8ff".to_string(),
                extension: "jpg".to_string(),
            }],
            total_scanned: 1000,
            total_carved: 1,
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("JPEG"));
    }

    #[test]
    fn test_add_custom_signature() {
        let mut carver = FileCarver::new();
        carver.add_custom_signature("TEST", "test", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let mut data = vec![0u8; 200];
        data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let tmp = std::env::temp_dir().join("carve_custom");
        std::fs::create_dir_all(&tmp).unwrap();
        let result = carver.carve_file(&data, tmp.to_str().unwrap());
        assert_eq!(result.total_carved, 1);
        assert_eq!(result.files[0].file_type, "TEST");
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_carve_multiple_formats() {
        let carver = FileCarver::new();
        let mut data = vec![0u8; 5000];
        data[0..3].copy_from_slice(&[0xFF, 0xD8, 0xFF]);
        data[400..404].copy_from_slice(&[0x89, 0x50, 0x4E, 0x47]);

        let tmp = std::env::temp_dir().join("carve_multi");
        std::fs::create_dir_all(&tmp).unwrap();
        let result = carver.carve_file(&data, tmp.to_str().unwrap());
        assert!(result.total_carved >= 1);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
