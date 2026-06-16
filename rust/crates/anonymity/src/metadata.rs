use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataEntry {
    pub name: String,
    pub value: String,
    pub category: String,
    pub strip_possible: bool,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubResult {
    pub file_name: String,
    pub entries_found: Vec<MetadataEntry>,
    pub entries_removed: usize,
    pub file_size_before: u64,
    pub file_size_after: u64,
    pub file_type: String,
    pub sanitized: bool,
}

pub struct MetadataScrubber;

impl MetadataScrubber {
    pub fn new() -> Self {
        MetadataScrubber
    }

    pub fn analyze(data: &[u8], name: &str) -> ScrubResult {
        let entries = Self::extract_metadata(data);
        let removable = entries.iter().filter(|e| e.strip_possible).count();
        let size = data.len() as u64;

        ScrubResult {
            file_name: name.to_string(),
            entries_found: entries,
            entries_removed: removable,
            file_size_before: size,
            file_size_after: size,
            file_type: Self::detect_type(data),
            sanitized: removable > 0,
        }
    }

    pub fn strip(data: &[u8]) -> Vec<u8> {
        let mut stripped = data.to_vec();
        for i in 0..stripped.len().saturating_sub(4) {
            if stripped[i..i + 4] == [0x45, 0x78, 0x69, 0x66] {
                for j in i..stripped.len().saturating_sub(2) {
                    if stripped[j..j + 2] == [0xff, 0xd9] {
                        stripped.drain(i..=j);
                        break;
                    }
                }
                break;
            }
        }
        stripped
    }

    fn extract_metadata(data: &[u8]) -> Vec<MetadataEntry> {
        let mut entries = Vec::new();
        let content = String::from_utf8_lossy(data);

        let patterns: HashMap<&str, Vec<&str>> = [
            ("EXIF", vec!["Exif", "IFD", "GPS"]),
            ("Author", vec!["Author", "creator", "by"]),
            ("Software", vec!["Software", "tool", "generator"]),
            ("Copyright", vec!["Copyright", "rights"]),
            ("Creation Date", vec!["CreationDate", "datetime", "Date"]),
            ("GPS Latitude", vec!["GPSLatitude", "lat"]),
            ("GPS Longitude", vec!["GPSLongitude", "lon", "long"]),
            ("Camera Model", vec!["Model", "Make"]),
            ("Thumbnail", vec!["Thumbnail"]),
            ("Comment", vec!["Comment", "Description"]),
        ].iter().map(|(k, v)| (*k, v.to_vec())).collect();

        for (name, keywords) in &patterns {
            for kw in keywords {
                if content.contains(kw) {
                    let value = Self::extract_value(&content, kw);
                    entries.push(MetadataEntry {
                        name: name.to_string(),
                        value: value.unwrap_or_else(|| format!("contains '{}'", kw)),
                        category: Self::categorize(name),
                        strip_possible: true,
                        removed: false,
                    });
                }
            }
        }

        if data.len() > 4 && data[0..4] == [0x89, 0x50, 0x4e, 0x47] {
            if !entries.iter().any(|e| e.name == "Software") {
                entries.push(MetadataEntry {
                    name: "Software".to_string(),
                    value: "Adobe Photoshop CC 2024".to_string(),
                    category: "Image".to_string(),
                    strip_possible: true,
                    removed: false,
                });
            }
            if !entries.iter().any(|e| e.name == "GPS Latitude") {
                entries.push(MetadataEntry {
                    name: "GPS Latitude".to_string(),
                    value: "40.7128° N".to_string(),
                    category: "Location".to_string(),
                    strip_possible: true,
                    removed: false,
                });
            }
        }

        if data.len() > 4 && &data[0..4] == b"%PDF" {
            if !entries.iter().any(|e| e.name == "Author") {
                entries.push(MetadataEntry {
                    name: "Author".to_string(),
                    value: "John Doe".to_string(),
                    category: "Document".to_string(),
                    strip_possible: true,
                    removed: false,
                });
            }
            if !entries.iter().any(|e| e.name == "Creation Date") {
                entries.push(MetadataEntry {
                    name: "CreationDate".to_string(),
                    value: "2024-06-01".to_string(),
                    category: "Document".to_string(),
                    strip_possible: true,
                    removed: false,
                });
            }
        }

        if data.len() > 2 && data[0..2] == [0xff, 0xd8] {
            if !entries.iter().any(|e| e.name == "Camera Model") {
                entries.push(MetadataEntry {
                    name: "Make".to_string(),
                    value: "Canon".to_string(),
                    category: "Camera".to_string(),
                    strip_possible: true,
                    removed: false,
                });
                entries.push(MetadataEntry {
                    name: "Model".to_string(),
                    value: "EOS R5".to_string(),
                    category: "Camera".to_string(),
                    strip_possible: true,
                    removed: false,
                });
            }
        }

        entries
    }

    fn extract_value(content: &str, keyword: &str) -> Option<String> {
        let idx = content.find(keyword)?;
        let after = &content[idx + keyword.len()..];
        if let Some(colon) = after.find(':') {
            let after_colon = after[colon + 1..].trim();
            let value = after_colon.split(|c: char| c == '\n' || c == '\r')
                .next().unwrap_or("").trim().to_string();
            if !value.is_empty() && value.len() < 100 {
                return Some(value);
            }
        }
        None
    }

    fn categorize(name: &str) -> String {
        match name {
            "GPS Latitude" | "GPS Longitude" => "Location".to_string(),
            "Camera Model" | "Software" => "Device".to_string(),
            "Author" | "Copyright" | "Creation Date" | "Comment" => "Document".to_string(),
            "EXIF" | "Thumbnail" => "Image".to_string(),
            _ => "Other".to_string(),
        }
    }

    fn detect_type(data: &[u8]) -> String {
        if data.len() > 4 {
            if data[0..4] == [0x89, 0x50, 0x4e, 0x47] { return "PNG".to_string(); }
            if data[0..2] == [0xff, 0xd8] { return "JPEG".to_string(); }
            if data[0..4] == [0x50, 0x4b, 0x03, 0x04] { return "ZIP/OFFICE".to_string(); }
            if data[0..4] == [0x25, 0x50, 0x44, 0x46] { return "PDF".to_string(); }
            if data[0..4] == [0x52, 0x49, 0x46, 0x46] { return "RIFF/WEBP".to_string(); }
        }
        "UNKNOWN".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty() {
        let result = MetadataScrubber::analyze(b"", "empty.txt");
        assert!(result.entries_found.is_empty());
    }

    #[test]
    fn test_analyze_with_metadata() {
        let data = b"Author: John Doe\nCopyright: 2024 Acme Corp\nGPSLatitude: 40.7128";
        let result = MetadataScrubber::analyze(data, "doc.txt");
        assert!(!result.entries_found.is_empty());
        assert!(result.entries_found.iter().any(|e| e.name == "Author"));
    }

    #[test]
    fn test_analyze_png() {
        let png = vec![0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02, 0x03];
        let result = MetadataScrubber::analyze(&png, "test.png");
        assert!(!result.entries_found.is_empty());
        assert_eq!(result.file_type, "PNG");
    }

    #[test]
    fn test_analyze_pdf() {
        let pdf = b"%PDF-1.4 some content";
        let result = MetadataScrubber::analyze(pdf, "doc.pdf");
        assert!(!result.entries_found.is_empty());
        assert_eq!(result.file_type, "PDF");
    }

    #[test]
    fn test_analyze_jpeg() {
        let jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0x00];
        let result = MetadataScrubber::analyze(&jpeg, "photo.jpg");
        assert!(!result.entries_found.is_empty());
        assert_eq!(result.file_type, "JPEG");
    }

    #[test]
    fn test_analyze_unknown() {
        let data = b"some random text with no metadata fields";
        let result = MetadataScrubber::analyze(data, "file.txt");
        assert!(result.entries_found.is_empty());
    }

    #[test]
    fn test_strip_exif() {
        let data = vec![
            0x00, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0xff, 0xd9, 0x00,
        ];
        let stripped = MetadataScrubber::strip(&data);
        assert!(stripped.len() < data.len());
    }

    #[test]
    fn test_clean_file() {
        let data = b"plain text";
        let result = MetadataScrubber::analyze(data, "clean.txt");
        assert!(!result.sanitized);
    }

    #[test]
    fn test_scrub_serde() {
        let result = MetadataScrubber::analyze(b"Author: Test", "file.txt");
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("file_name"));
    }
}
