use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareDiffResult {
    pub version_a: String,
    pub version_b: String,
    pub total_changes: usize,
    pub new_sections: Vec<DiffEntry>,
    pub removed_sections: Vec<DiffEntry>,
    pub modified_regions: Vec<DiffEntry>,
    pub vulnerability_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub offset: u64,
    pub size: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytePattern {
    pub offset: u64,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
    pub changed: bool,
}

pub struct FirmwareDiffer;

impl FirmwareDiffer {
    pub fn new() -> Self {
        FirmwareDiffer
    }

    pub fn diff(old: &[u8], new: &[u8], label_a: &str, label_b: &str) -> FirmwareDiffResult {
        let diffs = Self::byte_diff(old, new);
        let (new_sections, removed_sections, modified, indicators) = Self::classify_changes(&diffs, old, new);

        FirmwareDiffResult {
            version_a: label_a.to_string(),
            version_b: label_b.to_string(),
            total_changes: diffs.len(),
            new_sections,
            removed_sections,
            modified_regions: modified,
            vulnerability_indicators: indicators,
        }
    }

    fn byte_diff(old: &[u8], new: &[u8]) -> Vec<BytePattern> {
        let mut patterns = Vec::new();
        let max_len = old.len().max(new.len());
        let chunk = 64usize;
        let mut pos = 0usize;

        while pos < max_len {
            let old_chunk = if pos < old.len() {
                &old[pos..old.len().min(pos + chunk)]
            } else {
                &[]
            };
            let new_chunk = if pos < new.len() {
                &new[pos..new.len().min(pos + chunk)]
            } else {
                &[]
            };

            let changed = old_chunk != new_chunk;
            if changed {
                patterns.push(BytePattern {
                    offset: pos as u64,
                    old_bytes: old_chunk.to_vec(),
                    new_bytes: new_chunk.to_vec(),
                    changed,
                });
            }
            pos += chunk;
        }

        patterns
    }

    fn classify_changes(
        patterns: &[BytePattern],
        old: &[u8],
        new: &[u8],
    ) -> (Vec<DiffEntry>, Vec<DiffEntry>, Vec<DiffEntry>, Vec<String>) {
        let mut new_sections = Vec::new();
        let mut removed_sections = Vec::new();
        let mut modified = Vec::new();
        let mut indicators = Vec::new();

        for p in patterns {
            if !p.changed {
                continue;
            }

            let old_empty = p.old_bytes.iter().all(|&b| b == 0) || p.old_bytes.is_empty();
            let new_empty = p.new_bytes.iter().all(|&b| b == 0) || p.new_bytes.is_empty();

            if old_empty && !new_empty {
                new_sections.push(DiffEntry {
                    offset: p.offset,
                    size: p.new_bytes.len() as u64,
                    description: "New content added".to_string(),
                });
            } else if !old_empty && new_empty {
                removed_sections.push(DiffEntry {
                    offset: p.offset,
                    size: p.old_bytes.len() as u64,
                    description: "Content removed".to_string(),
                });
            } else {
                let desc = if p.old_bytes.len() >= 4 && p.new_bytes.len() >= 4
                    && p.old_bytes[..4] != p.new_bytes[..4]
                {
                    let old_magic = Self::hex_prefix(&p.old_bytes);
                    let new_magic = Self::hex_prefix(&p.new_bytes);
                    format!("Modified: {} -> {}", old_magic, new_magic)
                } else {
                    let delta = Self::count_diff(&p.old_bytes, &p.new_bytes);
                    format!("Modified ({} bytes differ)", delta)
                };
                modified.push(DiffEntry {
                    offset: p.offset,
                    size: p.old_bytes.len().max(p.new_bytes.len()) as u64,
                    description: desc,
                });
            }
        }

        if old.len() != new.len() {
            indicators.push(format!(
                "Firmware size changed: {} -> {} bytes (delta: {})",
                old.len(),
                new.len(),
                if new.len() > old.len() {
                    (new.len() - old.len()) as isize
                } else {
                    -((old.len() - new.len()) as isize)
                }
            ));
        }

        (new_sections, removed_sections, modified, indicators)
    }

    fn hex_prefix(data: &[u8]) -> String {
        let len = data.len().min(8);
        data[..len].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
    }

    fn count_diff(a: &[u8], b: &[u8]) -> usize {
        let max = a.len().max(b.len());
        let mut count = 0;
        for i in 0..max {
            let ba = a.get(i).copied().unwrap_or(0);
            let bb = b.get(i).copied().unwrap_or(0);
            if ba != bb {
                count += 1;
            }
        }
        count
    }

    pub fn find_version_strings(data: &[u8]) -> Vec<String> {
        let mut versions = Vec::new();
        if let Ok(s) = std::str::from_utf8(data) {
            let re = regex::Regex::new(r"(?i)(version|ver\.?|v)\s*[0-9]+\.[0-9]+(\.[0-9]+)?")
                .unwrap();
            for cap in re.find_iter(s) {
                versions.push(cap.as_str().to_string());
            }
        }
        versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_identical() {
        let data = b"hello world";
        let result = FirmwareDiffer::diff(data, data, "v1", "v2");
        assert_eq!(result.total_changes, 0);
    }

    #[test]
    fn test_diff_different() {
        let old = b"hello world";
        let new = b"hello kraken";
        let result = FirmwareDiffer::diff(old, new, "v1", "v2");
        assert!(result.total_changes > 0);
    }

    #[test]
    fn test_diff_size_change() {
        let old = b"short";
        let new = b"longer content here";
        let result = FirmwareDiffer::diff(old, new, "v1", "v2");
        assert!(result.total_changes > 0);
        assert!(result.vulnerability_indicators.iter().any(|i| i.contains("size changed")));
    }

    #[test]
    fn test_byte_diff_exact() {
        let patterns = FirmwareDiffer::byte_diff(b"AAAA", b"AABA");
        let changed: Vec<_> = patterns.iter().filter(|p| p.changed).collect();
        assert_eq!(changed.len(), 1);
    }

    #[test]
    fn test_find_version_strings() {
        let data = b"this is version 2.1.3 of the firmware";
        let versions = FirmwareDiffer::find_version_strings(data);
        assert!(versions.iter().any(|v| v.contains("2.1.3")));
    }

    #[test]
    fn test_diff_result_serde() {
        let result = FirmwareDiffResult {
            version_a: "v1".to_string(),
            version_b: "v2".to_string(),
            total_changes: 0,
            new_sections: vec![],
            removed_sections: vec![],
            modified_regions: vec![],
            vulnerability_indicators: vec![],
        };
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("v1"));
    }
}
