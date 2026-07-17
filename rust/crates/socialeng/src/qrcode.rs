

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QrPhishConfig {
    pub url: String,
    pub output_path: String,
    pub size: u32,
    pub error_correction: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QrCodeResult {
    pub url: String,
    pub output_path: String,
    pub format: String,
    pub generated_at: String,
}

pub struct QrPhish;

impl Default for QrPhish {
    fn default() -> Self {
        Self::new()
    }
}

impl QrPhish {
    pub fn new() -> Self {
        QrPhish
    }

    pub fn generate(url: &str, output_path: &str) -> QrCodeResult {
        QrCodeResult {
            url: url.to_string(),
            output_path: output_path.to_string(),
            format: "ascii".to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn generate_ascii(url: &str) -> String {
        let mut qr = String::new();
        qr.push_str("QR Code for: ");
        qr.push_str(url);
        qr.push('\n');

        let size = 25;
        let quiet = 2;
        let total = size + quiet * 2;

        let seed: u64 = url.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));

        for row in 0..total {
            for col in 0..total {
                if row < quiet || row >= total - quiet || col < quiet || col >= total - quiet {
                    qr.push('█');
                } else {
                    let r = row - quiet;
                    let c = col - quiet;
                    let idx = r * size + c;
                    let bit = ((seed >> (idx % 63)) & 1) != 0;
                    let border = r == 0 || r == size - 1 || c == 0 || c == size - 1;
                    let finder = (r < 7 && c < 7) || (r < 7 && c >= size - 7) || (r >= size - 7 && c < 7);
                    if finder {
                        let _inner = (r > 0 && r < 6) && (c > 0 && c < 6) && !((r == 1 || r == 5) && (0..7).contains(&c)) && !((c == 1 || c == 5) && (0..7).contains(&r));
                        let is_outer = r == 0 || r == 6 || c == 0 || c == 6;
                        if is_outer || ((2..=4).contains(&r) && (2..=4).contains(&c)) {
                            qr.push('█');
                        } else {
                            qr.push(' ');
                        }
                    } else if border || bit {
                        qr.push('█');
                    } else {
                        qr.push(' ');
                    }
                }
            }
            qr.push('\n');
        }
        qr
    }

    pub fn encode_url(original_url: &str, redirect_to: &str) -> String {
        let encoded = urlencoding(redirect_to);
        format!("{}?r={}", original_url, encoded)
    }

    pub fn generate_tracking_pixel(tracking_url: &str, campaign_id: &str) -> String {
        format!(
            r#"<img src="{}/track/{}/pixel.png" width="1" height="1" style="display:none" />"#,
            tracking_url.trim_end_matches('/'),
            campaign_id
        )
    }
}

fn urlencoding(input: &str) -> String {
    let mut result = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b' ' => result.push_str("%20"),
            _ => result.push_str(&format!("%{:02X}", byte)),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ascii() {
        let ascii = QrPhish::generate_ascii("http://evil.com/login");
        assert!(ascii.contains("http://evil.com/login"));
        assert!(ascii.contains('█'));
    }

    #[test]
    fn test_generate() {
        let result = QrPhish::generate("http://evil.com", "/tmp/qr.txt");
        assert_eq!(result.url, "http://evil.com");
        assert_eq!(result.output_path, "/tmp/qr.txt");
    }

    #[test]
    fn test_encode_url() {
        let encoded = QrPhish::encode_url("http://evil.com", "http://target.com/login");
        assert!(encoded.contains("r="));
    }

    #[test]
    fn test_generate_tracking_pixel() {
        let pixel = QrPhish::generate_tracking_pixel("http://tracker.com", "campaign_1");
        assert!(pixel.contains("tracker.com/track/campaign_1/pixel.png"));
        assert!(pixel.contains("width=\"1\""));
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding("hello world"), "hello%20world");
        assert_eq!(urlencoding("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    #[test]
    fn test_qr_code_result() {
        let r = QrCodeResult {
            url: "http://evil.com".to_string(),
            output_path: "qr.png".to_string(),
            format: "ascii".to_string(),
            generated_at: "now".to_string(),
        };
        let json = serde_json::to_string_pretty(&r).unwrap();
        assert!(json.contains("evil.com"));
    }
}
