use crate::{Finding, Severity};
use std::io::Write;
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
