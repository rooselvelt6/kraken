use crate::{Finding, FindingStatus, ScanResult, Severity};
use std::io::Write;
use std::path::Path;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

pub fn generate_cli_report(findings: &[Finding]) {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);

    writeln!(&mut stdout, "\n=== Vulnerability Scan Report ===\n").unwrap();

    if findings.is_empty() {
        writeln!(&mut stdout, "No vulnerabilities found.").unwrap();
        return;
    }

    let mut by_severity: Vec<(Severity, Vec<&Finding>)> = vec![
        (Severity::Critical, vec![]),
        (Severity::High, vec![]),
        (Severity::Medium, vec![]),
        (Severity::Low, vec![]),
        (Severity::Info, vec![]),
    ];

    for f in findings {
        match f.severity {
            Severity::Critical => by_severity[0].1.push(f),
            Severity::High => by_severity[1].1.push(f),
            Severity::Medium => by_severity[2].1.push(f),
            Severity::Low => by_severity[3].1.push(f),
            Severity::Info => by_severity[4].1.push(f),
        }
    }

    for (sev, finds) in &by_severity {
        if finds.is_empty() {
            continue;
        }

        let color = match sev {
            Severity::Critical => Color::Red,
            Severity::High => Color::Magenta,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Cyan,
            Severity::Info => Color::Green,
        };

        stdout
            .set_color(ColorSpec::new().set_fg(Some(color)).set_bold(true))
            .unwrap();
        writeln!(
            &mut stdout,
            "[{}] {} findings",
            format!("{:?}", sev),
            finds.len()
        )
        .unwrap();
        stdout.reset().unwrap();

        for f in finds {
            writeln!(&mut stdout, "  - {}", f.description).unwrap();
            if let Some(path) = &f.file_path {
                writeln!(&mut stdout, "    File: {}", path.display()).unwrap();
            }
            if let Some(line) = f.line_number {
                writeln!(&mut stdout, "    Line: {}", line).unwrap();
            }
            if let Some(cwe) = &f.cwe {
                writeln!(&mut stdout, "    CWE: {}", cwe).unwrap();
            }
            writeln!(&mut stdout).unwrap();
        }
    }

    writeln!(&mut stdout, "Total: {} findings", findings.len()).unwrap();
}

pub fn generate_json_report(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string())
}

pub fn print_summary(findings: &[Finding]) {
    let mut stdout = StandardStream::stdout(ColorChoice::Auto);
    let counts = [
        (Severity::Critical, 0),
        (Severity::High, 0),
        (Severity::Medium, 0),
        (Severity::Low, 0),
        (Severity::Info, 0),
    ];

    let mut actual_counts = counts;
    for f in findings {
        match f.severity {
            Severity::Critical => actual_counts[0].1 += 1,
            Severity::High => actual_counts[1].1 += 1,
            Severity::Medium => actual_counts[2].1 += 1,
            Severity::Low => actual_counts[3].1 += 1,
            Severity::Info => actual_counts[4].1 += 1,
        }
    }

    write!(&mut stdout, "Scan complete: ").unwrap();
    stdout.set_color(ColorSpec::new().set_bold(true)).unwrap();
    writeln!(&mut stdout, "{} findings", findings.len()).unwrap();
    stdout.reset().unwrap();

    for (sev, count) in &actual_counts {
        if *count > 0 {
            let color = match sev {
                Severity::Critical => Color::Red,
                Severity::High => Color::Magenta,
                Severity::Medium => Color::Yellow,
                Severity::Low => Color::Cyan,
                Severity::Info => Color::Green,
            };
            stdout
                .set_color(ColorSpec::new().set_fg(Some(color)))
                .unwrap();
            write!(&mut stdout, "  {}: {}", format!("{:?}", sev), count).unwrap();
            stdout.reset().unwrap();
            writeln!(&mut stdout).unwrap();
        }
    }
}

fn severity_color(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "#dc3545",
        Severity::High => "#fd7e14",
        Severity::Medium => "#ffc107",
        Severity::Low => "#0dcaf0",
        Severity::Info => "#20c997",
    }
}

fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn status_label(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "Open",
        FindingStatus::Confirmed => "Confirmed",
        FindingStatus::InTriage => "In Triage",
        FindingStatus::Reported => "Reported",
        FindingStatus::Accepted => "Accepted",
        FindingStatus::Patched => "Patched",
        FindingStatus::Fixed => "Fixed",
        FindingStatus::FalsePositive => "False Positive",
        FindingStatus::WonTFix => "Won't Fix",
    }
}

fn status_color(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::Open => "#dc3545",
        FindingStatus::Confirmed => "#fd7e14",
        FindingStatus::InTriage => "#ffc107",
        FindingStatus::Reported => "#0d6efd",
        FindingStatus::Accepted => "#6f42c1",
        FindingStatus::Patched => "#20c997",
        FindingStatus::Fixed => "#198754",
        FindingStatus::FalsePositive => "#6c757d",
        FindingStatus::WonTFix => "#adb5bd",
    }
}

pub fn generate_html_report(findings: &[Finding], result: &ScanResult) -> String {
    let counts = [
        (Severity::Critical, result.critical_count),
        (Severity::High, result.high_count),
        (Severity::Medium, result.medium_count),
        (Severity::Low, result.low_count),
        (Severity::Info, result.info_count),
    ];

    let total = result.total_findings;
    let max_count = counts.iter().map(|(_, c)| c).max().unwrap_or(&1).max(&1);

    let mut severity_bars = String::new();
    for (sev, count) in &counts {
        let pct = if *max_count > 0 {
            (*count as f64 / *max_count as f64) * 100.0
        } else {
            0.0
        };
        severity_bars.push_str(&format!(
            r#"<div class="bar-row"><span class="bar-label">{sev}</span><div class="bar-track"><div class="bar-fill" style="width:{pct:.0}%;background:{color}"></div></div><span class="bar-count">{count}</span></div>"#,
            sev = severity_label(sev),
            color = severity_color(sev),
        ));
    }

    let mut cvss_buckets = [0u32; 11];
    for f in findings {
        if let Some(score) = f.cvss_score {
            let bucket = (score.floor() as usize).min(10);
            cvss_buckets[bucket] += 1;
        }
    }
    let cvss_max = cvss_buckets.iter().max().unwrap_or(&1).max(&1);
    let mut cvss_bars = String::new();
    for (i, count) in cvss_buckets.iter().enumerate() {
        let pct = (*count as f64 / *cvss_max as f64) * 100.0;
        let color = if i <= 3 {
            "#20c997"
        } else if i <= 6 {
            "#ffc107"
        } else {
            "#dc3545"
        };
        cvss_bars.push_str(&format!(
            r#"<div class="cvss-bar"><div class="cvss-label">{i}</div><div class="bar-track"><div class="bar-fill" style="width:{pct:.0}%;background:{color}"></div></div><div class="cvss-count">{count}</div></div>"#,
        ));
    }

    let mut timeline_dates: Vec<String> = Vec::new();
    for f in findings {
        let s = f.discovered_at.format("%Y-%m-%d").to_string();
        if !timeline_dates.contains(&s) {
            timeline_dates.push(s);
        }
    }
    timeline_dates.sort();
    let mut timeline_items = String::new();
    for date in &timeline_dates {
        let count = findings
            .iter()
            .filter(|f| f.discovered_at.format("%Y-%m-%d").to_string() == *date)
            .count();
        timeline_items.push_str(&format!(
            r#"<div class="timeline-item"><span class="timeline-date">{date}</span><span class="timeline-dot"></span><span class="timeline-count">{count} finding(s)</span></div>"#,
        ));
    }

    let mut table_rows = String::new();
    for f in findings {
        let sev_col = severity_color(&f.severity);
        let sev_lbl = severity_label(&f.severity);
        let cwe = f.cwe.as_deref().unwrap_or("-");
        let desc = html_escape(&f.description);
        let file = f
            .file_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string());
        let st_lbl = status_label(&f.status);
        let st_col = status_color(&f.status);
        let cvss = f
            .cvss_score
            .map(|s| format!("{:.1}", s))
            .unwrap_or_else(|| "-".to_string());

        table_rows.push_str(&format!(
            r#"<tr><td><span class="severity-badge" style="background:{sev_col}">{sev_lbl}</span></td><td>{cwe}</td><td>{desc}</td><td class="file-cell">{file}</td><td><span class="status-badge" style="background:{st_col}">{st_lbl}</span></td><td>{cvss}</td></tr>"#,
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Scan Report</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:#0d1117;color:#c9d1d9;padding:0;line-height:1.6}}
.header{{background:#161b22;border-bottom:1px solid #30363d;padding:2rem;text-align:center}}
.header h1{{font-size:1.8rem;color:#f0f6fc;margin-bottom:0.5rem}}
.header p{{color:#8b949e;font-size:0.95rem}}
.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;padding:2rem;max-width:1200px;margin:0 auto}}
.summary-card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;text-align:center}}
.summary-card .count{{font-size:2rem;font-weight:700}}
.summary-card .label{{font-size:0.85rem;color:#8b949e;margin-top:0.25rem}}
.section{{max-width:1200px;margin:2rem auto;padding:0 2rem}}
.section h2{{font-size:1.3rem;color:#f0f6fc;margin-bottom:1rem;border-bottom:1px solid #30363d;padding-bottom:0.5rem}}
.bar-row{{display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem}}
.bar-label{{width:80px;font-size:0.9rem;font-weight:600;text-align:right}}
.bar-track{{flex:1;height:24px;background:#21262d;border-radius:4px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:4px;transition:width 0.3s ease;min-width:2px}}
.bar-count{{width:40px;text-align:right;font-weight:600;font-size:0.9rem}}
.cvss-dist{{display:flex;gap:0.25rem;align-items:flex-end;height:160px;padding:0 0.5rem}}
.cvss-bar{{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px}}
.cvss-bar .bar-track{{width:100%;height:120px;display:flex;align-items:flex-end}}
.cvss-bar .bar-fill{{width:100%;min-height:2px;border-radius:3px 3px 0 0}}
.cvss-label{{font-size:0.75rem;color:#8b949e}}
.cvss-count{{font-size:0.75rem;font-weight:600}}
.timeline{{position:relative;padding-left:1.5rem}}
.timeline::before{{content:'';position:absolute;left:6px;top:8px;bottom:8px;width:2px;background:#30363d}}
.timeline-item{{display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem}}
.timeline-dot{{width:12px;height:12px;border-radius:50%;background:#58a6ff;border:2px solid #0d1117;flex-shrink:0}}
.timeline-date{{font-weight:600;min-width:100px}}
.timeline-count{{color:#8b949e;font-size:0.9rem}}
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:0.9rem}}
th,td{{padding:0.6rem 0.75rem;text-align:left;border-bottom:1px solid #21262d}}
th{{background:#161b22;color:#8b949e;font-weight:600;position:sticky;top:0}}
tr:hover td{{background:#1c2128}}
.severity-badge,.status-badge{{display:inline-block;padding:0.15rem 0.5rem;border-radius:4px;font-size:0.8rem;font-weight:600;color:#fff}}
.file-cell{{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.footer{{text-align:center;padding:2rem;color:#8b949e;font-size:0.85rem;border-top:1px solid #30363d;margin-top:2rem}}
@media(max-width:768px){{.summary-grid{{grid-template-columns:repeat(2,1fr)}}.section{{padding:0 1rem}}.file-cell{{max-width:150px}}}}
</style>
</head>
<body>
<div class="header">
<h1>🔍 Vulnerability Scan Report</h1>
<p>Files scanned: {files} | Total findings: {total} | Duration: {dur}ms</p>
</div>
<div class="summary-grid">
{cards}
</div>
<div class="section">
<h2>Severity Distribution</h2>
{sev_bars}
</div>
<div class="section">
<h2>CVSS Score Distribution</h2>
<div class="cvss-dist">
{cvss}
</div>
</div>
<div class="section">
<h2>Timeline</h2>
<div class="timeline">
{timeline}
</div>
</div>
<div class="section">
<h2>Findings</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Severity</th><th>CWE</th><th>Description</th><th>File</th><th>Status</th><th>CVSS</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</div>
</div>
<div class="footer">
Generated by Kraken Vulnerability Scanner | {now}
</div>
</body>
</html>"#,
        cards = counts.iter().map(|(sev, count)| {
            let label = severity_label(sev);
            format!(
                r#"<div class="summary-card"><div class="count" style="color:{color}">{count}</div><div class="label">{label}</div></div>"#,
                color = severity_color(sev),
            )
        }).collect::<Vec<_>>().join("\n"),
        files = result.files_scanned,
        total = total,
        dur = result.duration_ms,
        sev_bars = severity_bars,
        cvss = cvss_bars,
        timeline = timeline_items,
        rows = table_rows,
        now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    );

    html
}

pub fn save_html_report(
    findings: &[Finding],
    result: &ScanResult,
    path: &Path,
) -> std::io::Result<()> {
    let html = generate_html_report(findings, result);
    std::fs::write(path, html)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
