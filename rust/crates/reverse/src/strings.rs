use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    pub value: String,
    pub offset: u64,
    pub type_name: String,
    pub length: usize,
}

pub struct StringExtractor;

impl StringExtractor {
    pub fn extract<P: AsRef<Path>>(path: P, min_length: usize) -> Result<Vec<StringEntry>, String> {
        let data = std::fs::read(path.as_ref())
            .map_err(|e| format!("Cannot read file: {}", e))?;

        let mut strings = Vec::new();
        Self::extract_ascii(&data, min_length, &mut strings);
        Self::extract_unicode(&data, min_length, &mut strings);

        strings.sort_by_key(|a| a.offset);
        Ok(strings)
    }

    pub fn extract_ascii(data: &[u8], min_length: usize, results: &mut Vec<StringEntry>) {
        let mut start = None;
        for (i, &byte) in data.iter().enumerate() {
            if byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' {
                if start.is_none() {
                    start = Some(i);
                }
            } else {
                if let Some(s) = start.take() {
                    let length = i - s;
                    if length >= min_length {
                        if let Ok(value) = std::str::from_utf8(&data[s..i]) {
                            results.push(StringEntry {
                                value: value.to_string(),
                                offset: s as u64,
                                type_name: "ASCII".to_string(),
                                length,
                            });
                        }
                    }
                }
            }
        }
        if let Some(s) = start.take() {
            let length = data.len() - s;
            if length >= min_length {
                if let Ok(value) = std::str::from_utf8(&data[s..]) {
                    results.push(StringEntry {
                        value: value.to_string(),
                        offset: s as u64,
                        type_name: "ASCII".to_string(),
                        length,
                    });
                }
            }
        }
    }

    pub fn extract_unicode(data: &[u8], min_length: usize, results: &mut Vec<StringEntry>) {
        let min_chars = min_length;
        let mut start = None;
        let mut i = 0;
        while i + 1 < data.len() {
            if data[i] != 0 && data[i + 1] == 0 && data[i].is_ascii_graphic() {
                if start.is_none() {
                    start = Some(i);
                }
                i += 2;
            } else {
                if let Some(s) = start.take() {
                    let chars_count = (i - s) / 2;
                    if chars_count >= min_chars {
                        let value: String = (s..i).step_by(2)
                            .filter_map(|j| {
                                if data[j].is_ascii() { Some(data[j] as char) } else { None }
                            })
                            .collect();
                        if !value.is_empty() {
                            results.push(StringEntry {
                                value,
                                offset: s as u64,
                                type_name: "UTF-16LE".to_string(),
                                length: chars_count,
                            });
                        }
                    }
                }
                i += 1;
            }
        }
        if let Some(s) = start.take() {
            let chars_count = (data.len() - s) / 2;
            if chars_count >= min_chars {
                let value: String = (s..data.len()).step_by(2)
                    .filter_map(|j| {
                        if data[j].is_ascii() { Some(data[j] as char) } else { None }
                    })
                    .collect();
                if !value.is_empty() {
                    results.push(StringEntry {
                        value,
                        offset: s as u64,
                        type_name: "UTF-16LE".to_string(),
                        length: chars_count,
                    });
                }
            }
        }
    }

    pub fn extract_urls(strings: &[StringEntry]) -> Vec<&StringEntry> {
        let url_re = regex::Regex::new(r"(https?://[^\s]+)").ok();
        strings.iter().filter(|s| {
            url_re.as_ref().is_some_and(|re| re.is_match(&s.value))
        }).collect()
    }

    pub fn extract_emails(strings: &[StringEntry]) -> Vec<&StringEntry> {
        let email_re = regex::Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").ok();
        strings.iter().filter(|s| {
            email_re.as_ref().is_some_and(|re| re.is_match(&s.value))
        }).collect()
    }

    pub fn extract_ip_addresses(strings: &[StringEntry]) -> Vec<&StringEntry> {
        let ip_re = regex::Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").ok();
        strings.iter().filter(|s| {
            ip_re.as_ref().is_some_and(|re| re.is_match(&s.value))
        }).collect()
    }
}

pub fn format_strings(strings: &[StringEntry], max_count: usize) -> String {
    if strings.is_empty() {
        return "No strings found.".to_string();
    }

    let count = strings.len().min(max_count);
    let mut out = format!("Strings found: {} (showing {})\n\n", strings.len(), count);

    for entry in strings.iter().take(count) {
        out.push_str(&format!("  {:#x} ({:>6}) [{}] {}\n",
            entry.offset, entry.length, entry.type_name,
            entry.value.escape_debug()));
    }

    if strings.len() > max_count {
        out.push_str(&format!("  ... and {} more\n", strings.len() - max_count));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"hello\x00world\x00test123\x00";
        let mut results = Vec::new();
        StringExtractor::extract_ascii(data, 3, &mut results);
        assert!(results.len() >= 3);
        assert!(results.iter().any(|s| s.value == "hello"));
        assert!(results.iter().any(|s| s.value == "world"));
    }

    #[test]
    fn test_extract_unicode_strings() {
        let mut data = Vec::new();
        for &c in b"test" {
            data.push(c);
            data.push(0);
        }
        let mut results = Vec::new();
        StringExtractor::extract_unicode(&data, 2, &mut results);
        assert!(!results.is_empty());
        assert_eq!(results[0].value, "test");
    }

    #[test]
    fn test_extract_urls() {
        let strings = vec![
            StringEntry { value: "https://example.com".to_string(), offset: 0, type_name: "ASCII".to_string(), length: 20 },
            StringEntry { value: "hello world".to_string(), offset: 20, type_name: "ASCII".to_string(), length: 11 },
        ];
        let urls = StringExtractor::extract_urls(&strings);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].value, "https://example.com");
    }

    #[test]
    fn test_extract_emails() {
        let strings = vec![
            StringEntry { value: "test@example.com".to_string(), offset: 0, type_name: "ASCII".to_string(), length: 16 },
            StringEntry { value: "not an email".to_string(), offset: 16, type_name: "ASCII".to_string(), length: 13 },
        ];
        let emails = StringExtractor::extract_emails(&strings);
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].value, "test@example.com");
    }

    #[test]
    fn test_extract_ip_addresses() {
        let strings = vec![
            StringEntry { value: "192.168.1.1".to_string(), offset: 0, type_name: "ASCII".to_string(), length: 11 },
            StringEntry { value: "not an ip".to_string(), offset: 11, type_name: "ASCII".to_string(), length: 10 },
        ];
        let ips = StringExtractor::extract_ip_addresses(&strings);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_min_length_filter() {
        let data = b"a\nbb\nccc\ndddd\n";
        let mut results = Vec::new();
        StringExtractor::extract_ascii(data, 4, &mut results);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "dddd");
    }

    #[test]
    fn test_format_no_strings() {
        let formatted = format_strings(&[], 100);
        assert_eq!(formatted, "No strings found.");
    }

    #[test]
    fn test_string_entry() {
        let entry = StringEntry {
            value: "hello".to_string(),
            offset: 0x1000,
            type_name: "ASCII".to_string(),
            length: 5,
        };
        assert_eq!(entry.value, "hello");
        assert_eq!(entry.offset, 0x1000);
    }
}
