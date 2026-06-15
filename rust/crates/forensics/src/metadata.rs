use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataResult {
    pub file_path: String,
    pub file_size: u64,
    pub mime_type: Option<String>,
    pub exif: HashMap<String, String>,
    pub gps: Option<GpsData>,
    pub embedded_metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GpsData {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: Option<f64>,
}

pub struct MetadataExtractor;

impl MetadataExtractor {
    pub fn new() -> Self {
        MetadataExtractor
    }

    pub fn extract(path: &str) -> Result<MetadataResult, String> {
        let file_path = Path::new(path);
        if !file_path.exists() {
            return Err("File not found".to_string());
        }

        let meta = std::fs::metadata(path).map_err(|e| format!("metadata failed: {}", e))?;
        let file_size = meta.len();

        let data = std::fs::read(path).map_err(|e| format!("read failed: {}", e))?;

        let mime_type = Self::detect_mime(&data);
        let exif = Self::extract_exif(&data);
        let gps = Self::extract_gps(&data);
        let embedded_metadata = Self::extract_embedded(&data);

        Ok(MetadataResult {
            file_path: path.to_string(),
            file_size,
            mime_type,
            exif,
            gps,
            embedded_metadata,
        })
    }

    fn detect_mime(data: &[u8]) -> Option<String> {
        if data.len() < 4 { return None; }
        match &data[..4] {
            [0xFF, 0xD8, 0xFF, _] => Some("image/jpeg".to_string()),
            [0x89, 0x50, 0x4E, 0x47] => Some("image/png".to_string()),
            [0x47, 0x49, 0x46, 0x38] => Some("image/gif".to_string()),
            [0x25, 0x50, 0x44, 0x46] => Some("application/pdf".to_string()),
            [0x50, 0x4B, 0x03, 0x04] => Some("application/zip".to_string()),
            [0x52, 0x61, 0x72, 0x21] => Some("application/vnd.rar".to_string()),
            [0x42, 0x4D, _, _] => Some("image/bmp".to_string()),
            [0x49, 0x49, 0x2A, 0x00] => Some("image/tiff".to_string()),
            [0x4D, 0x4D, 0x00, 0x2A] => Some("image/tiff".to_string()),
            [0x7F, 0x45, 0x4C, 0x46] => Some("application/x-elf".to_string()),
            [0x4D, 0x5A, _, _] => Some("application/x-dosexec".to_string()),
            _ => None,
        }
    }

    fn extract_exif(data: &[u8]) -> HashMap<String, String> {
        let mut exif = HashMap::new();
        let exif_start = Self::find_exif_header(data);
        if let Some(start) = exif_start {
            let chunk = &data[start..data.len().min(start + 1000)];
            let tags = vec![
                (0x010F, "Make"),
                (0x0110, "Model"),
                (0x0112, "Orientation"),
                (0x0132, "DateTimeOriginal"),
                (0x010E, "ImageDescription"),
                (0x013B, "Artist"),
                (0x0102, "Software"),
                (0x0103, "Copyright"),
                (0x011A, "XResolution"),
                (0x011B, "YResolution"),
            ];
            for (tag, name) in tags {
                if let Some(value) = Self::read_exif_tag(chunk, tag) {
                    exif.insert(name.to_string(), value);
                }
            }
        }
        exif
    }

    fn find_exif_header(data: &[u8]) -> Option<usize> {
        data.windows(6)
            .position(|w| w == b"Exif\0\0")
            .or_else(|| {
                data.windows(4)
                    .position(|w| w == b"II\x2A\x00" || w == b"MM\x00\x2A")
            })
    }

    fn read_exif_tag(data: &[u8], tag: u16) -> Option<String> {
        for i in (8..data.len().saturating_sub(12)).step_by(2) {
            if i + 2 <= data.len() {
                let entry_tag = u16::from_be_bytes([data[i], data[i + 1]]);
                if entry_tag == tag {
                    let type_field = u16::from_be_bytes([data[i + 2], data[i + 3]]);
                    let _count = u32::from_be_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
                    if type_field == 2 && i + 12 <= data.len() {
                        let val = &data[i + 8..i + 12];
                        let s = String::from_utf8_lossy(val).trim_end_matches('\0').to_string();
                        if !s.is_empty() {
                            return Some(s);
                        }
                    }
                }
            }
        }
        None
    }

    fn extract_gps(data: &[u8]) -> Option<GpsData> {
        let gps_start = data.windows(6).position(|w| w == b"Exif\0\0")? + 6;
        let chunk = &data[gps_start..data.len().min(gps_start + 500)];
        let gps_pos = chunk.windows(4).position(|w| w == [0x00, 0x02, 0x00, 0x00])?;
        let gps_data = &chunk[gps_pos..gps_pos + 200];

        if gps_data.len() < 24 { return None; }
        let lat = f64::from(gps_data[8]) + f64::from(gps_data[9]) / 60.0;
        let lon = f64::from(gps_data[16]) + f64::from(gps_data[17]) / 60.0;

        if (lat - 0.0).abs() > 0.001 || (lon - 0.0).abs() > 0.001 {
            Some(GpsData { latitude: lat, longitude: lon, altitude: None })
        } else {
            None
        }
    }

    fn extract_embedded(data: &[u8]) -> HashMap<String, String> {
        let mut meta = HashMap::new();
        if let Ok(text) = std::str::from_utf8(data) {
            for line in text.lines() {
                let line = line.trim();
                if let Some((key, val)) = line.split_once(':') {
                    let k = key.trim().to_lowercase();
                    let interesting = ["creator", "producer", "author", "title", "subject",
                        "keywords", "createdate", "moddate", "generator", "application"];
                    if interesting.iter().any(|i| k.contains(i)) {
                        meta.insert(k, val.trim().to_string());
                    }
                }
            }
        }
        meta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_mime_jpeg() {
        assert_eq!(MetadataExtractor::detect_mime(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg".to_string()));
    }

    #[test]
    fn test_detect_mime_png() {
        assert_eq!(MetadataExtractor::detect_mime(&[0x89, 0x50, 0x4E, 0x47]), Some("image/png".to_string()));
    }

    #[test]
    fn test_detect_mime_pdf() {
        assert_eq!(MetadataExtractor::detect_mime(&[0x25, 0x50, 0x44, 0x46]), Some("application/pdf".to_string()));
    }

    #[test]
    fn test_detect_mime_unknown() {
        assert_eq!(MetadataExtractor::detect_mime(&[0x00, 0x01, 0x02, 0x03]), None);
    }

    #[test]
    fn test_extract_exif_empty() {
        let exif = MetadataExtractor::extract_exif(&[0u8; 100]);
        assert!(exif.is_empty());
    }

    #[test]
    fn test_find_exif_header() {
        let mut data = vec![0u8; 100];
        data[50..56].copy_from_slice(b"Exif\0\0");
        assert_eq!(MetadataExtractor::find_exif_header(&data), Some(50));
    }

    #[test]
    fn test_gps_data() {
        let gps = GpsData { latitude: 10.5, longitude: -66.0, altitude: None };
        assert!((gps.latitude - 10.5).abs() < 0.001);
    }

    #[test]
    fn test_metadata_result() {
        let mut exif = HashMap::new();
        exif.insert("Model".to_string(), "iPhone 15".to_string());
        let result = MetadataResult {
            file_path: "/tmp/photo.jpg".to_string(),
            file_size: 1024,
            mime_type: Some("image/jpeg".to_string()),
            exif,
            gps: None,
            embedded_metadata: HashMap::new(),
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("image/jpeg"));
    }

    #[test]
    fn test_extract_nonexistent() {
        let result = MetadataExtractor::extract("/nonexistent/photo.jpg");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_embedded_metadata() {
        let data = b"Creator: John\nProducer: TestApp\nSomeOther: Value\n";
        let meta = MetadataExtractor::extract_embedded(data);
        assert!(meta.contains_key("creator"));
        assert!(meta.contains_key("producer"));
        assert!(!meta.contains_key("someother"));
    }
}
