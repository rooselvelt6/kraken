use std::collections::HashMap;

use kraken_errors::ForensicsError;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PdfInfo {
    pub file_path: String,
    pub file_size: u64,
    pub version: Option<String>,
    pub page_count: Option<usize>,
    pub metadata: HashMap<String, String>,
    pub suspicious_elements: Vec<String>,
    pub objects: Vec<PdfObject>,
    pub streams: Vec<PdfStream>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PdfObject {
    pub id: u32,
    pub gen: u32,
    pub obj_type: String,
    pub size: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PdfStream {
    pub obj_id: u32,
    pub length: usize,
    pub filter: Option<String>,
    pub content_preview: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PdfForensics;

impl Default for PdfForensics {
    fn default() -> Self {
        Self::new()
    }
}

impl PdfForensics {
    pub fn new() -> Self {
        PdfForensics
    }

    pub fn analyze(path: &str) -> Result<PdfInfo, ForensicsError> {
        let data = std::fs::read(path)?;
        if !data.starts_with(b"%PDF-") {
            return Err(ForensicsError::Parse("Not a valid PDF file".to_string()));
        }

        let version = Self::extract_version(&data);
        let page_count = Self::count_pages(&data);
        let metadata = Self::extract_metadata(&data);
        let suspicious_elements = Self::detect_suspicious(&data);
        let objects = Self::extract_objects(&data);
        let streams = Self::extract_streams(&data);
        let file_size = data.len() as u64;

        Ok(PdfInfo {
            file_path: path.to_string(),
            file_size,
            version,
            page_count,
            metadata,
            suspicious_elements,
            objects,
            streams,
        })
    }

    fn extract_version(data: &[u8]) -> Option<String> {
        let s = std::str::from_utf8(data).ok()?;
        let first_line = s.lines().next()?;
        if first_line.starts_with('%') {
            let v = first_line.strip_prefix('%').unwrap_or(first_line).trim();
            if v.starts_with("PDF-") {
                return Some(v.to_string());
            }
        }
        None
    }

    fn count_pages(data: &[u8]) -> Option<usize> {
        let text = std::str::from_utf8(data).ok()?;
        let count = text.matches("/Type /Page").count()
            + text.matches("/Type/Page").count();
        if count > 0 { Some(count) } else { None }
    }

    fn extract_metadata(data: &[u8]) -> HashMap<String, String> {
        let mut meta = HashMap::new();
        let text = std::str::from_utf8(data).unwrap_or("");
        let fields = ["Title", "Author", "Subject", "Keywords", "Creator",
            "Producer", "CreationDate", "ModDate", "Trapped"];

        for field in &fields {
            let pattern = format!("/{}", field);
            if let Some(pos) = text.find(&pattern) {
                let rest = &text[pos + pattern.len()..];
                if let Some(content) = rest.split(&['(', '\n', '\r'][..]).nth(1) {
                    if let Some(end) = content.find(')') {
                        let value = content[..end].to_string();
                        meta.insert(field.to_string(), value);
                    }
                }
            }
        }

        if let Some(info_start) = text.find("/Info ") {
            let info_rest = &text[info_start..];
            if let Some(stream_end) = info_rest.find(">>") {
                let info_block = &info_rest[..stream_end + 2];
                for field in &fields {
                    let pattern = format!("/{}", field);
                    if let Some(pos) = info_block.find(&pattern) {
                        let rest = &info_block[pos + pattern.len()..];
                        if let Some(content) = rest.split(&['(', '\n', '\r'][..]).nth(1) {
                            if let Some(end) = content.find(')') {
                                meta.insert(field.to_string(), content[..end].to_string());
                            }
                        }
                    }
                }
            }
        }

        meta
    }

    fn detect_suspicious(data: &[u8]) -> Vec<String> {
        let mut alerts = Vec::new();
        let text = std::str::from_utf8(data).unwrap_or("");

        let patterns: Vec<(&str, &str)> = vec![
            ("/JavaScript", "JavaScript detected"),
            ("/JS", "JS action detected"),
            ("/Launch", "Launch action detected"),
            ("/EmbeddedFile", "Embedded file detected"),
            ("/OpenAction", "Open action detected"),
            ("/AA", "Additional action detected"),
            ("/URI", "URI action detected"),
            ("/SubmitForm", "Form submission detected"),
            ("/RichMedia", "Rich media content detected"),
            ("/Flash", "Flash content detected"),
            ("/AcroForm", "AcroForm detected"),
        ];

        for (pattern, alert) in &patterns {
            if text.contains(pattern) {
                alerts.push(alert.to_string());
            }
        }

        if text.contains("endobj") {
            let obj_count = text.matches("endobj").count();
            if obj_count > 500 {
                alerts.push(format!("Large number of objects: {}", obj_count));
            }
        }

        alerts
    }

    fn extract_objects(data: &[u8]) -> Vec<PdfObject> {
        let mut objects = Vec::new();
        let text = std::str::from_utf8(data).unwrap_or("");
        let re = match regex::Regex::new(r"(\d+)\s+(\d+)\s+obj") {
            Ok(r) => r,
            Err(_) => return objects,
        };
        for cap in re.captures_iter(text) {
            let id: u32 = cap[1].parse().unwrap_or(0);
            let gen: u32 = cap[2].parse().unwrap_or(0);
            objects.push(PdfObject {
                id,
                gen,
                obj_type: "unknown".to_string(),
                size: 0,
            });
        }
        objects
    }

    fn extract_streams(data: &[u8]) -> Vec<PdfStream> {
        let mut streams = Vec::new();
        let text = std::str::from_utf8(data).unwrap_or("");
        let re = match regex::Regex::new(r"(\d+)\s+\d+\s+obj.*?stream") {
            Ok(r) => r,
            Err(_) => return streams,
        };
        for cap in re.captures_iter(text) {
            let obj_id: u32 = cap[1].parse().unwrap_or(0);
            let preview_end = text.find(&cap[0]).map(|p| (p + cap[0].len()).min(text.len())).unwrap_or(0);
            let preview = &text[preview_end..(preview_end + 80).min(text.len())];

            let filter = if text[..preview_end].contains("/FlateDecode") {
                Some("FlateDecode".to_string())
            } else if text[..preview_end].contains("/ASCIIHexDecode") {
                Some("ASCIIHexDecode".to_string())
            } else if text[..preview_end].contains("/ASCII85Decode") {
                Some("ASCII85Decode".to_string())
            } else {
                None
            };

            streams.push(PdfStream {
                obj_id,
                length: 0,
                filter,
                content_preview: preview.chars().take(60).collect(),
            });
        }
        streams
    }

    pub fn extract_text_simple(data: &[u8]) -> String {
        let text = std::str::from_utf8(data).unwrap_or("");
        let mut result = String::new();
        let mut in_stream = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("stream") { in_stream = true; continue; }
            if trimmed.starts_with("endstream") { in_stream = false; continue; }
            if trimmed.starts_with("BT") && in_stream {
                let text_content: String = trimmed
                    .split('(')
                    .filter_map(|s| s.split(')').next())
                    .collect::<Vec<_>>()
                    .join(" ");
                if !text_content.is_empty() {
                    result.push_str(&text_content);
                    result.push(' ');
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_pdf() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"%PDF-1.4\n");
        data.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        data.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        data.extend_from_slice(b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n");
        data.extend_from_slice(b"xref\n");
        data.extend_from_slice(b"trailer\n<< /Info 1 0 R /Root 1 0 R /Size 4 >>\n");
        data.extend_from_slice(b"startxref\n0\n%%EOF\n");
        data
    }

    #[test]
    fn test_analyze_valid_pdf() {
        let tmp = std::env::temp_dir().join("test.pdf");
        std::fs::write(&tmp, create_test_pdf()).unwrap();
        let result = PdfForensics::analyze(tmp.to_str().unwrap());
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.version.unwrap(), "PDF-1.4");
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_analyze_invalid() {
        let result = PdfForensics::analyze("/nonexistent/file.pdf");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_version() {
        let data = b"%PDF-2.0\n%%EOF";
        assert_eq!(PdfForensics::extract_version(data), Some("PDF-2.0".to_string()));
    }

    #[test]
    fn test_count_pages() {
        let data = b"<< /Type /Page >> << /Type /Page >>";
        assert_eq!(PdfForensics::count_pages(data), Some(2));
    }

    #[test]
    fn test_detect_suspicious() {
        let data = b"some data /JavaScript more data /Launch end";
        let alerts = PdfForensics::detect_suspicious(data);
        assert!(alerts.contains(&"JavaScript detected".to_string()));
        assert!(alerts.contains(&"Launch action detected".to_string()));
    }

    #[test]
    fn test_extract_objects() {
        let data = b"1 0 obj\n<< >>\nendobj\n2 5 obj\n<< >>\nendobj\n";
        let objects = PdfForensics::extract_objects(data);
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].id, 1);
        assert_eq!(objects[1].gen, 5);
    }

    #[test]
    fn test_pdf_info_serialize() {
        let mut meta = HashMap::new();
        meta.insert("Author".to_string(), "Test".to_string());
        let info = PdfInfo {
            file_path: "test.pdf".to_string(),
            file_size: 100,
            version: Some("PDF-1.7".to_string()),
            page_count: Some(5),
            metadata: meta,
            suspicious_elements: vec![],
            objects: vec![],
            streams: vec![],
        };
        let json = serde_json::to_string_pretty(&info).unwrap();
        assert!(json.contains("test.pdf"));
        assert!(json.contains("PDF-1.7"));
    }

    #[test]
    fn test_extract_text_simple() {
        let data = b"stream\nBT (Hello World) Tj ET\nBT (Page 2) Tj ET\nendstream";
        let text = PdfForensics::extract_text_simple(data);
        assert!(!text.is_empty());
    }
}
