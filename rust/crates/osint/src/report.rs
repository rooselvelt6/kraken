use std::collections::HashMap;

use crate::{FindingKind, OsintReport, Reliability};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReportFormat {
    Json,
    Html,
    Markdown,
    Csv,
    Text,
}

#[derive(Debug, Clone)]
pub struct ReportGenerator;

impl ReportGenerator {
    pub fn generate(report: &OsintReport, format: ReportFormat) -> String {
        match format {
            ReportFormat::Json => Self::to_json(report),
            ReportFormat::Html => Self::to_html(report),
            ReportFormat::Markdown => Self::to_markdown(report),
            ReportFormat::Csv => Self::to_csv(report),
            ReportFormat::Text => Self::to_text(report),
        }
    }

    pub fn to_json(report: &OsintReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(report: &OsintReport) -> String {
        let mut out = String::new();
        out.push_str("===== OSINT REPORT =====\n");
        out.push_str(&format!("Target: {} ({:?})\n", report.target.value, report.target.kind));
        out.push_str(&format!("Collected: {}\n", report.collected_at));
        out.push_str(&format!("{}\n", report.summary));
        out.push_str("==========================\n\n");

        let grouped = Self::group_by_kind(report);
        let mut kinds: Vec<_> = grouped.keys().collect();
        kinds.sort_by(|a, b| {
            let a_score = grouped.get(*a).map(|v: &Vec<_>| v.iter().map(|f| f.confidence).sum::<f64>()).unwrap_or(0.0);
            let b_score = grouped.get(*b).map(|v: &Vec<_>| v.iter().map(|f| f.confidence).sum::<f64>()).unwrap_or(0.0);
            b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
        });

        for kind in kinds {
            let findings = &grouped[kind];
            out.push_str(&format!("--- {} ({}) ---\n", kind, findings.len()));

            for finding in findings {
                let reliability = match finding.source.reliability {
                    Reliability::High => "HIGH",
                    Reliability::Medium => "MED",
                    Reliability::Low => "LOW",
                    Reliability::Untrusted => "UNTRUSTED",
                };

                out.push_str(&format!("  [{:>9}] {} [{:.0}%]\n", reliability, finding.value, finding.confidence * 100.0));

                if let Some(ref ctx) = finding.context {
                    out.push_str(&format!("          {}\n", ctx));
                }
                if let Some(ref url) = finding.source.url {
                    out.push_str(&format!("          {}\n", url));
                }
            }
            out.push('\n');
        }

        out
    }

    pub fn to_markdown(report: &OsintReport) -> String {
        let mut out = String::new();
        out.push_str(&format!("# OSINT Report: {}\n\n", report.target.value));
        out.push_str(&format!("- **Target**: `{}` ({:?})\n", report.target.value, report.target.kind));
        out.push_str(&format!("- **Collected**: {}\n", report.collected_at));
        out.push_str(&format!("- **Summary**: {}\n\n", report.summary));

        let grouped = Self::group_by_kind(report);
        let mut kinds: Vec<_> = grouped.keys().collect();
        kinds.sort();

        for kind in kinds {
            let findings = &grouped[kind];
            out.push_str(&format!("## {} ({})\n\n", kind, findings.len()));

            for finding in findings {
                let badge = match finding.source.reliability {
                    Reliability::High => "🟢",
                    Reliability::Medium => "🟡",
                    Reliability::Low => "🟠",
                    Reliability::Untrusted => "🔴",
                };

                out.push_str(&format!("{} **{}** (confidence: {:.0}%)\n", badge, finding.value, finding.confidence * 100.0));
                if let Some(ref ctx) = finding.context {
                    out.push_str(&format!("   - {}\n", ctx));
                }
                if let Some(ref url) = finding.source.url {
                    out.push_str(&format!("   - [Source]({})\n", url));
                }
                out.push('\n');
            }
        }

        out
    }

    pub fn to_html(report: &OsintReport) -> String {
        let grouped = Self::group_by_kind(report);
        let mut kinds: Vec<_> = grouped.keys().collect();
        kinds.sort();

        let mut findings_html = String::new();
        for kind in kinds {
            let findings = &grouped[kind];
            findings_html.push_str(&format!(
                r#"<div class="section"><h2>{} <span class="count">({})</span></h2>"#,
                Self::escape_html(kind),
                findings.len()
            ));

            for finding in findings {
                let badge_class = match finding.source.reliability {
                    Reliability::High => "badge-high",
                    Reliability::Medium => "badge-med",
                    Reliability::Low => "badge-low",
                    Reliability::Untrusted => "badge-untrusted",
                };
                let badge_text = match finding.source.reliability {
                    Reliability::High => "HIGH",
                    Reliability::Medium => "MED",
                    Reliability::Low => "LOW",
                    Reliability::Untrusted => "UNTRUSTED",
                };

                findings_html.push_str(&format!(
                    r#"<div class="finding"><span class="badge {}">{}</span> <strong>{}</strong> <span class="conf">{:.0}%</span>"#,
                    badge_class, badge_text, Self::escape_html(&finding.value), finding.confidence * 100.0
                ));

                if let Some(ref ctx) = finding.context {
                    findings_html.push_str(&format!("<div class=\"ctx\">{}</div>", Self::escape_html(ctx)));
                }
                if let Some(ref url) = finding.source.url {
                    findings_html.push_str(&format!("<div class=\"url\"><a href=\"{}\">{}</a></div>", Self::escape_html(url), Self::escape_html(url)));
                }
                findings_html.push_str("</div>\n");
            }
            findings_html.push_str("</div>\n");
        }

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report: {target}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 0 auto; padding: 20px; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #8b949e; margin-top: 30px; }}
  .meta {{ color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }}
  .summary {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; margin-bottom: 25px; }}
  .section {{ margin-bottom: 10px; }}
  .count {{ color: #58a6ff; font-size: 0.7em; }}
  .finding {{ background: #161b22; border: 1px solid #21262d; border-radius: 4px; padding: 10px; margin: 8px 0; }}
  .finding:hover {{ border-color: #30363d; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.7em; font-weight: bold; margin-right: 8px; }}
  .badge-high {{ background: #1b4332; color: #7ecba1; }}
  .badge-med {{ background: #3d2e00; color: #e3b341; }}
  .badge-low {{ background: #3d1a00; color: #e37a41; }}
  .badge-untrusted {{ background: #3d0000; color: #e34141; }}
  .conf {{ color: #8b949e; font-size: 0.85em; }}
  .ctx {{ color: #8b949e; font-size: 0.85em; margin-top: 4px; padding-left: 4px; border-left: 2px solid #30363d; }}
  .url {{ margin-top: 4px; font-size: 0.85em; }}
  .url a {{ color: #58a6ff; text-decoration: none; }}
  .url a:hover {{ text-decoration: underline; }}
  .footer {{ margin-top: 40px; color: #484f58; font-size: 0.8em; text-align: center; border-top: 1px solid #30363d; padding-top: 15px; }}
</style>
</head>
<body>
<h1>🕵️ OSINT Report</h1>
<div class="meta">
  <strong>Target:</strong> <code>{target}</code> ({kind})<br>
  <strong>Collected:</strong> {date}<br>
  <strong>Sources:</strong> {sources}
</div>
<div class="summary">{summary}</div>
{findings}
<div class="footer">Generated by Kraken OSINT &mdash; {date}</div>
</body>
</html>"#,
            target = Self::escape_html(&report.target.value),
            kind = Self::escape_html(&format!("{:?}", report.target.kind)),
            date = Self::escape_html(&report.collected_at),
            sources = report.source_count,
            summary = Self::escape_html(&report.summary),
            findings = findings_html,
        )
    }

    pub fn to_csv(report: &OsintReport) -> String {
        let mut out = String::new();
        out.push_str("kind,value,source,reliability,confidence,context,url,timestamp\n");

        for finding in &report.findings {
            let kind = Self::csv_escape(&format!("{:?}", finding.kind));
            let value = Self::csv_escape(&finding.value);
            let source = Self::csv_escape(&finding.source.name);
            let reliability = format!("{:?}", finding.source.reliability);
            let confidence = format!("{:.2}", finding.confidence);
            let context = Self::csv_escape(finding.context.as_deref().unwrap_or(""));
            let url = Self::csv_escape(finding.source.url.as_deref().unwrap_or(""));
            let timestamp = Self::csv_escape(&finding.timestamp);
            out.push_str(&format!("{},{},{},{},{},{},{},{}\n", kind, value, source, reliability, confidence, context, url, timestamp));
        }

        out
    }

    fn group_by_kind(report: &OsintReport) -> HashMap<String, Vec<&crate::OsintFinding>> {
        let mut map: HashMap<String, Vec<&crate::OsintFinding>> = HashMap::new();
        for finding in &report.findings {
            let key = Self::kind_label(&finding.kind);
            map.entry(key).or_default().push(finding);
        }
        map
    }

    fn kind_label(kind: &FindingKind) -> String {
        match kind {
            FindingKind::Email => "Email".into(),
            FindingKind::Url => "URL".into(),
            FindingKind::IpAddress => "IP Address".into(),
            FindingKind::PhoneNumber => "Phone".into(),
            FindingKind::Username => "Username".into(),
            FindingKind::DnsRecord => "DNS".into(),
            FindingKind::WhoisInfo => "WHOIS".into(),
            FindingKind::Technology => "Technology".into(),
            FindingKind::Subdomain => "Subdomain".into(),
            FindingKind::SocialProfile => "Social Profile".into(),
            FindingKind::BreachData => "Breach".into(),
            FindingKind::Custom(s) => s.clone(),
        }
    }

    fn escape_html(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    fn csv_escape(s: &str) -> String {
        if s.contains(',') || s.contains('"') || s.contains('\n') {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FindingKind, OsintFinding, OsintReport, OsintSource, OsintTarget, Reliability, TargetKind};

    fn make_report() -> OsintReport {
        let target = OsintTarget { value: "example.com".into(), kind: TargetKind::Domain };
        let findings = vec![
            OsintFinding {
                source: OsintSource { name: "dns/A".into(), reliability: Reliability::High, url: None },
                kind: FindingKind::IpAddress,
                value: "93.184.216.34".into(),
                context: Some("Resolved via A record".into()),
                confidence: 0.95,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
            OsintFinding {
                source: OsintSource { name: "social/GitHub".into(), reliability: Reliability::Medium, url: Some("https://github.com/testuser".into()) },
                kind: FindingKind::SocialProfile,
                value: "GitHub: testuser".into(),
                context: Some("Profile exists".into()),
                confidence: 0.8,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
        ];
        OsintReport::new(target, findings)
    }

    #[test]
    fn generates_json() {
        let report = make_report();
        let json = ReportGenerator::to_json(&report);
        assert!(json.contains("example.com"));
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("GitHub"));
    }

    #[test]
    fn generates_html() {
        let report = make_report();
        let html = ReportGenerator::to_html(&report);
        assert!(html.contains("<h1>"));
        assert!(html.contains("example.com"));
        assert!(html.contains("93.184.216.34"));
        assert!(html.contains("</html>"));
        assert!(html.contains("OSINT Report"));
    }

    #[test]
    fn generates_text() {
        let report = make_report();
        let text = ReportGenerator::to_text(&report);
        assert!(text.contains("OSINT REPORT"));
        assert!(text.contains("example.com"));
        assert!(text.contains("93.184.216.34"));
    }

    #[test]
    fn generates_markdown() {
        let report = make_report();
        let md = ReportGenerator::to_markdown(&report);
        assert!(md.contains("# OSINT Report"));
        assert!(md.contains("example.com"));
        assert!(md.contains("93.184.216.34"));
    }

    #[test]
    fn generates_csv() {
        let report = make_report();
        let csv = ReportGenerator::to_csv(&report);
        assert!(csv.contains("kind,value"));
        assert!(csv.contains("93.184.216.34"));
        assert!(csv.contains("dns/A"));
    }

    #[test]
    fn generate_dispatches_correctly() {
        let report = make_report();
        let json = ReportGenerator::generate(&report, ReportFormat::Json);
        let html = ReportGenerator::generate(&report, ReportFormat::Html);
        let md = ReportGenerator::generate(&report, ReportFormat::Markdown);
        let csv = ReportGenerator::generate(&report, ReportFormat::Csv);
        let text = ReportGenerator::generate(&report, ReportFormat::Text);

        assert!(json.starts_with('{'));
        assert!(html.starts_with("<!DOCTYPE"));
        assert!(md.starts_with('#'));
        assert!(csv.starts_with("kind"));
        assert!(text.starts_with("====="));
    }

    #[test]
    fn html_escapes_special_chars() {
        let target = OsintTarget { value: "test<>.com".into(), kind: TargetKind::Domain };
        let findings = vec![
            OsintFinding {
                source: OsintSource { name: "test/source".into(), reliability: Reliability::High, url: Some("https://example.com?a=b&c=d".into()) },
                kind: FindingKind::Url,
                value: "test\"value'".into(),
                context: Some("context with <>&".into()),
                confidence: 0.9,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
        ];
        let report = OsintReport::new(target, findings);
        let html = ReportGenerator::to_html(&report);
        assert!(html.contains("&lt;"));
        assert!(html.contains("&gt;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&quot;"));
        assert!(html.contains("&#39;"));
        assert!(!html.contains("<test"));
        assert!(!html.contains("\"value'"));
    }

    #[test]
    fn csv_escapes_commas() {
        let target = OsintTarget { value: "test".into(), kind: TargetKind::Domain };
        let findings = vec![
            OsintFinding {
                source: OsintSource { name: "source,with,commas".into(), reliability: Reliability::High, url: None },
                kind: FindingKind::Custom("custom,kind".into()),
                value: "value,with,commas".into(),
                context: Some("context,with,commas".into()),
                confidence: 0.9,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
        ];
        let report = OsintReport::new(target, findings);
        let csv = ReportGenerator::to_csv(&report);
        assert!(csv.contains('"'));
        assert!(csv.contains("custom,kind"));
        assert!(csv.contains("source,with,commas"));
    }

    #[test]
    fn empty_report_generates_all_formats() {
        let target = OsintTarget { value: "empty".into(), kind: TargetKind::Domain };
        let report = OsintReport::new(target, vec![]);

        assert!(!ReportGenerator::to_json(&report).is_empty());
        assert!(!ReportGenerator::to_html(&report).is_empty());
        assert!(!ReportGenerator::to_markdown(&report).is_empty());
        assert!(!ReportGenerator::to_csv(&report).is_empty());
        assert!(!ReportGenerator::to_text(&report).is_empty());
    }

    #[test]
    fn kind_label_all_variants() {
        assert_eq!(ReportGenerator::kind_label(&FindingKind::Email), "Email");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::Url), "URL");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::IpAddress), "IP Address");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::PhoneNumber), "Phone");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::Username), "Username");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::DnsRecord), "DNS");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::WhoisInfo), "WHOIS");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::Technology), "Technology");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::Subdomain), "Subdomain");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::SocialProfile), "Social Profile");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::BreachData), "Breach");
        assert_eq!(ReportGenerator::kind_label(&FindingKind::Custom("Test".into())), "Test");
    }

    #[test]
    fn report_format_equality() {
        assert_eq!(ReportFormat::Json, ReportFormat::Json);
        assert_ne!(ReportFormat::Json, ReportFormat::Html);
    }

    #[test]
    fn csv_no_escaping_needed() {
        let target = OsintTarget { value: "test".into(), kind: TargetKind::Domain };
        let findings = vec![OsintFinding {
            source: OsintSource { name: "simple".into(), reliability: Reliability::High, url: None },
            kind: FindingKind::Email,
            value: "user@example.com".into(),
            context: None,
            confidence: 0.9,
            timestamp: "2024-01-01T00:00:00Z".into(),
        }];
        let report = OsintReport::new(target, findings);
        let csv = ReportGenerator::to_csv(&report);
        assert!(!csv.contains('"'));
    }

    #[test]
    fn csv_escape_newlines() {
        let result = ReportGenerator::csv_escape("line1\nline2");
        assert!(result.contains("\""));
        assert!(result.contains("\n"));
    }

    #[test]
    fn html_multiple_findings_same_kind() {
        let target = OsintTarget { value: "test.com".into(), kind: TargetKind::Domain };
        let findings = vec![
            OsintFinding {
                source: OsintSource { name: "a".into(), reliability: Reliability::High, url: None },
                kind: FindingKind::IpAddress,
                value: "1.1.1.1".into(),
                context: None,
                confidence: 0.9,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
            OsintFinding {
                source: OsintSource { name: "b".into(), reliability: Reliability::Medium, url: None },
                kind: FindingKind::IpAddress,
                value: "2.2.2.2".into(),
                context: None,
                confidence: 0.8,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
        ];
        let report = OsintReport::new(target, findings);
        let html = ReportGenerator::to_html(&report);
        assert!(html.contains("(2)"));
    }

    #[test]
    fn markdown_reliability_badges() {
        let target = OsintTarget { value: "test.com".into(), kind: TargetKind::Domain };
        let findings = vec![
            OsintFinding {
                source: OsintSource { name: "a".into(), reliability: Reliability::High, url: None },
                kind: FindingKind::IpAddress,
                value: "1.1.1.1".into(),
                context: None,
                confidence: 0.9,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
            OsintFinding {
                source: OsintSource { name: "b".into(), reliability: Reliability::Low, url: None },
                kind: FindingKind::IpAddress,
                value: "2.2.2.2".into(),
                context: None,
                confidence: 0.5,
                timestamp: "2024-01-01T00:00:00Z".into(),
            },
        ];
        let report = OsintReport::new(target, findings);
        let md = ReportGenerator::to_markdown(&report);
        assert!(md.contains("IP Address (2)"));
    }
}
