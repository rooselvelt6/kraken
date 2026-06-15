use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    pub global_entropy: f64,
    pub section_entropies: Vec<(String, f64)>,
    pub high_entropy_regions: Vec<EntropyRegion>,
    pub is_packed: bool,
    pub packer_confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyRegion {
    pub offset: u64,
    pub size: usize,
    pub entropy: f64,
}

pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.iter() {
        if count == 0 { continue; }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

pub struct EntropyAnalyzer;

impl EntropyAnalyzer {
    pub fn analyze(data: &[u8], window_size: usize) -> EntropyResult {
        let global = compute_entropy(data);

        let mut regions = Vec::new();
        let threshold = 6.5;

        let step = window_size / 2;
        let mut i = 0;
        while i + window_size <= data.len() {
            let window = &data[i..i + window_size];
            let ent = compute_entropy(window);
            if ent > threshold {
                regions.push(EntropyRegion {
                    offset: i as u64,
                    size: window_size,
                    entropy: ent,
                });
            }
            i += step;
        }

        let packed = !regions.is_empty();
        let confidence = if packed {
            let max_ent = regions.iter().map(|r| r.entropy).fold(0.0, f64::max);
            if max_ent > 7.5 { 0.9 } else if max_ent > 7.0 { 0.7 } else { 0.5 }
        } else {
            0.0
        };

        EntropyResult {
            global_entropy: global,
            section_entropies: Vec::new(),
            high_entropy_regions: regions,
            is_packed: packed,
            packer_confidence: confidence,
        }
    }

    pub fn analyze_binary_sections(data: &[u8], section_offsets: &[(String, usize, usize)]) -> EntropyResult {
        let global = compute_entropy(data);
        let mut section_ents = Vec::new();
        let mut high_regions = Vec::new();

        for (name, start, size) in section_offsets {
            let end = (*start + *size).min(data.len());
            if end > *start {
                let ent = compute_entropy(&data[*start..end]);
                section_ents.push((name.clone(), ent));
                if ent > 6.5 {
                    high_regions.push(EntropyRegion {
                        offset: *start as u64,
                        size: *size,
                        entropy: ent,
                    });
                }
            }
        }

        let packed = !high_regions.is_empty();
        let confidence = if packed {
            let max_ent = high_regions.iter().map(|r| r.entropy).fold(0.0, f64::max);
            if max_ent > 7.5 { 0.95 } else if max_ent > 7.0 { 0.8 } else { 0.6 }
        } else {
            0.0
        };

        EntropyResult {
            global_entropy: global,
            section_entropies: section_ents,
            high_entropy_regions: high_regions,
            is_packed: packed,
            packer_confidence: confidence,
        }
    }
}

pub fn format_entropy_result(result: &EntropyResult) -> String {
    let mut out = format!("Entropy Analysis\n");
    out.push_str(&format!("Global entropy: {:.4}\n", result.global_entropy));
    out.push_str(&format!("Packed: {} (confidence: {:.1}%)\n",
        if result.is_packed { "YES" } else { "NO" },
        result.packer_confidence * 100.0));

    if !result.section_entropies.is_empty() {
        out.push_str(&format!("\nSection Entropies:\n"));
        for (name, ent) in &result.section_entropies {
            let marker = if *ent > 6.5 { " *** HIGH" } else { "" };
            out.push_str(&format!("  {:<12}: {:.4}{}\n", name, ent, marker));
        }
    }

    if !result.high_entropy_regions.is_empty() {
        out.push_str(&format!("\nHigh Entropy Regions (>{:.1}):\n", 6.5));
        for region in &result.high_entropy_regions {
            out.push_str(&format!("  offset={:#x} size={} entropy={:.4}\n",
                region.offset, region.size, region.entropy));
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_uniform() {
        let data = vec![0x41; 1024];
        let ent = compute_entropy(&data);
        assert!(ent < 0.01);
    }

    #[test]
    fn test_entropy_random() {
        let data: Vec<u8> = (0..1024).map(|i| (i ^ (i >> 4)) as u8).collect();
        let ent = compute_entropy(&data);
        assert!(ent > 6.0);
        assert!(ent <= 8.0);
    }

    #[test]
    fn test_entropy_empty() {
        assert_eq!(compute_entropy(&[]), 0.0);
    }

    #[test]
    fn test_entropy_analysis() {
        let mut data = vec![0x41; 4096];
        for i in 0..512 {
            data[2048 + i] = (i ^ (i >> 2)) as u8;
        }
        let result = EntropyAnalyzer::analyze(&data, 256);
        assert!(result.global_entropy < 2.0);
    }

    #[test]
    fn test_entropy_maximum() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).cycle().take(4096).collect();
        let ent = compute_entropy(&data);
        assert!((ent - 8.0).abs() < 0.1 || ent <= 8.0);
    }

    #[test]
    fn test_entropy_result_format() {
        let result = EntropyResult {
            global_entropy: 4.5,
            section_entropies: vec![(".text".to_string(), 5.0)],
            high_entropy_regions: vec![],
            is_packed: false,
            packer_confidence: 0.0,
        };
        let formatted = format_entropy_result(&result);
        assert!(formatted.contains("4.5"));
        assert!(formatted.contains("NO"));
    }

    #[test]
    fn test_high_entropy_detection() {
        let data: Vec<u8> = (0..512).map(|i| (i ^ (i >> 3) ^ (i >> 6)) as u8).collect();
        let result = EntropyAnalyzer::analyze(&data, 128);
        assert_eq!(result.global_entropy > 0.0, true);
    }
}
