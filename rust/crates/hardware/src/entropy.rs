use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub overall: f64,
    pub windows: Vec<EntropyWindow>,
    pub high_entropy_regions: Vec<EntropyRegion>,
    pub low_entropy_regions: Vec<EntropyRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyWindow {
    pub offset: u64,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyRegion {
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub avg_entropy: f64,
    pub classification: String,
}

pub struct EntropyScanner;

impl EntropyScanner {
    pub fn new() -> Self {
        EntropyScanner
    }

    pub fn scan(data: &[u8], window_size: usize) -> EntropyResult {
        let overall = Self::calculate_entropy(data);
        let windows = Self::sliding_window(data, window_size);
        let high = Self::find_regions(&windows, 7.5, window_size);
        let low = Self::find_regions(&windows, 3.0, window_size);

        EntropyResult {
            overall,
            windows,
            high_entropy_regions: high,
            low_entropy_regions: low,
        }
    }

    fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &byte in data {
            freq[byte as usize] = freq[byte as usize].wrapping_add(1);
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in freq.iter() {
            if count == 0 {
                continue;
            }
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
        entropy
    }

    fn sliding_window(data: &[u8], window: usize) -> Vec<EntropyWindow> {
        let mut windows = Vec::new();
        if data.len() < window {
            let e = Self::calculate_entropy(data);
            windows.push(EntropyWindow { offset: 0, value: e });
            return windows;
        }

        let step = window / 2;
        let mut pos = 0;
        while pos + window <= data.len() {
            let chunk = &data[pos..pos + window];
            let e = Self::calculate_entropy(chunk);
            windows.push(EntropyWindow {
                offset: pos as u64,
                value: e,
            });
            pos += step;
        }
        windows
    }

    fn find_regions(windows: &[EntropyWindow], threshold: f64, window_size: usize) -> Vec<EntropyRegion> {
        let mut regions = Vec::new();
        if windows.is_empty() {
            return regions;
        }

        let mut in_region = false;
        let mut start = 0u64;
        let mut sum = 0.0;
        let mut count = 0usize;

        for w in windows {
            let above = if threshold > 5.0 {
                w.value > threshold
            } else {
                w.value < threshold
            };

            if above && !in_region {
                in_region = true;
                start = w.offset;
                sum = w.value;
                count = 1;
            } else if above && in_region {
                sum += w.value;
                count += 1;
            } else if !above && in_region {
                let avg = sum / count as f64;
                let region_size = (w.offset - start) as u64 + window_size as u64 / 2;
                regions.push(EntropyRegion {
                    start,
                    end: w.offset,
                    size: region_size,
                    avg_entropy: avg,
                    classification: if threshold > 5.0 {
                        "encrypted/compressed"
                    } else {
                        "plain/zero"
                    }.to_string(),
                });
                in_region = false;
            }
        }

        if in_region {
            let last_offset = windows.last().unwrap().offset;
            let avg = sum / count as f64;
            regions.push(EntropyRegion {
                start,
                end: last_offset,
                size: last_offset - start + window_size as u64 / 2,
                avg_entropy: avg,
                classification: if threshold > 5.0 {
                    "encrypted/compressed"
                } else {
                    "plain/zero"
                }.to_string(),
            });
        }

        regions
    }

    pub fn classify_firmware(result: &EntropyResult) -> String {
        let high_ratio = result.high_entropy_regions.iter().map(|r| r.size).sum::<u64>() as f64
            / result.windows.last().map(|w| w.offset + 2048).max(Some(1)).unwrap_or(1) as f64;

        if high_ratio > 0.8 {
            "Likely encrypted firmware (proprietary)".to_string()
        } else if high_ratio > 0.4 {
            "Partially compressed/encrypted".to_string()
        } else if result.low_entropy_regions.iter().any(|r| r.size > 65536) {
            "Firmware with large plaintext section(s)".to_string()
        } else {
            "Standard firmware with mixed content".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_empty() {
        let result = EntropyScanner::scan(&[], 256);
        assert_eq!(result.overall, 0.0);
    }

    #[test]
    fn test_scan_uniform() {
        let data = vec![0x00u8; 4096];
        let result = EntropyScanner::scan(&data, 512);
        assert!(result.overall < 0.1);
        assert!(result.high_entropy_regions.is_empty());
    }

    #[test]
    fn test_scan_high_entropy() {
        let data: Vec<u8> = (0..255).cycle().take(8192).collect();
        let result = EntropyScanner::scan(&data, 512);
        assert!(result.overall > 7.0);
    }

    #[test]
    fn test_classify_encrypted() {
        let data: Vec<u8> = (0..255).cycle().take(4096).collect();
        let result = EntropyScanner::scan(&data, 512);
        let classification = EntropyScanner::classify_firmware(&result);
        assert!(classification.contains("encrypted"));
    }

    #[test]
    fn test_classify_plain() {
        let data = vec![0x41u8; 4096];
        let result = EntropyScanner::scan(&data, 512);
        let classification = EntropyScanner::classify_firmware(&result);
        assert!(classification.contains("plaintext") || classification.contains("mixed"));
    }

    #[test]
    fn test_sliding_window() {
        let data = vec![0x41u8; 4096];
        let windows = EntropyScanner::sliding_window(&data, 512);
        assert!(!windows.is_empty());
        for w in &windows {
            assert!(w.value < 0.1);
        }
    }
}
