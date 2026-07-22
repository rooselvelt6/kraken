use std::io::{self, Write};

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[91m";
pub const GREEN: &str = "\x1b[92m";
pub const YELLOW: &str = "\x1b[93m";
pub const BLUE: &str = "\x1b[94m";
pub const MAGENTA: &str = "\x1b[95m";
pub const CYAN: &str = "\x1b[96m";
pub const WHITE: &str = "\x1b[97m";
pub const BG_RED: &str = "\x1b[41m";
pub const BG_GREEN: &str = "\x1b[42m";
pub const BG_YELLOW: &str = "\x1b[43m";

pub fn severity_color(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "crit" => RED,
        "high" => YELLOW,
        "medium" | "med" => BLUE,
        "low" => CYAN,
        "info" | "informational" => DIM,
        "none" | "pass" => GREEN,
        _ => WHITE,
    }
}

pub fn print_banner() {
    let banner = format!(
        r#"{}{}
 __  __                  __            
|  \/  | ___  __ _  ___ / _| ___  _ __ 
| |\/| |/ _ \/ _` |/ _ \ |_ / _ \| '__|
| |  | |  __/ (_| | (_) |  _| (_) | |  
|_|  |_|\___|\__,_|\___/|_|  \___/|_|  v2.0{}"#,
        BOLD, CYAN, RESET
    );
    println!("{}", banner);
    println!(
        "{}  {}Enterprise Security Platform{}\n",
        DIM, WHITE, RESET
    );
}

pub fn print_header(title: &str) {
    let width = 60;
    let pad = width - title.len() - 4;
    let left = pad / 2;
    let right = pad - left;
    let top = format!("╔{} {} {}╗", "═".repeat(left), title, "═".repeat(right));
    let bot = format!("╚{}╝", "═".repeat(width - 2));
    println!("\n{}{}{}{}\n{}", BOLD, BLUE, top, bot, RESET);
}

pub fn print_section(title: &str) {
    println!(
        "\n{}{}── {} ──{}",
        BOLD, BLUE, title, RESET
    );
}

pub fn print_success(msg: &str) {
    println!("{}  ✓ {}{}", GREEN, msg, RESET);
}

pub fn print_error(msg: &str) {
    println!("{}  ✗ {}{}", RED, msg, RESET);
}

pub fn print_warning(msg: &str) {
    println!("{}  ⚠ {}{}", YELLOW, msg, RESET);
}

pub fn print_info(msg: &str) {
    println!("{}  ℹ {}{}", CYAN, msg, RESET);
}

pub fn print_kv(key: &str, value: &str) {
    println!("  {}{:<18}{} {}", BOLD, key, RESET, value);
}

pub fn print_finding(
    index: usize,
    title: &str,
    severity: &str,
    detail: Option<&str>,
) {
    let color = severity_color(severity);
    println!(
        "\n{}  #{} {}[{}]{} {}",
        DIM,
        index,
        color,
        severity.to_uppercase(),
        RESET,
        title,
    );
    if let Some(d) = detail {
        for line in d.lines() {
            println!("      {}{}{}", DIM, line, RESET);
        }
    }
}

pub fn print_progress_bar(label: &str, current: usize, total: usize, width: usize) {
    let pct = if total > 0 {
        current as f64 / total as f64
    } else {
        0.0
    };
    let filled = (pct * width as f64) as usize;
    let empty = width.saturating_sub(filled);
    let bar = format!("{}{}{}", "█".repeat(filled), "░".repeat(empty), RESET);
    print!(
        "\r  {} {:<20} [{}] {:.0}% ",
        BOLD, label, bar, pct * 100.0
    );
    let _ = io::stdout().flush();
}

pub fn print_table(headers: &[&str], rows: &[Vec<&str>]) {
    let col_widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let data_max = rows.iter().map(|r| r.get(i).map(|s| s.len()).unwrap_or(0)).max().unwrap_or(0);
            h.len().max(data_max)
        })
        .collect();

    print!("  {}{}", BOLD, BLUE);
    for (i, h) in headers.iter().enumerate() {
        print!("{:<width$}  ", h, width = col_widths[i]);
    }
    println!("{}", RESET);

    let total_width: usize = col_widths.iter().sum::<usize>() + (col_widths.len() - 1) * 2;
    println!("  {}{}{}", DIM, "─".repeat(total_width), RESET);

    for row in rows {
        print!("  ");
        for (i, cell) in row.iter().enumerate() {
            print!("{:<width$}  ", cell, width = col_widths[i]);
        }
        println!();
    }
}

pub fn print_summary_box(title: &str, items: &[(&str, &str)]) {
    let max_key = items.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let max_val = items.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
    let width = max_key + max_val + 6;

    println!("\n{}{}┌{}┐{}", BOLD, BLUE, "─".repeat(width), RESET);
    println!(
        "{}{}│{:^width$}│{}",
        BOLD,
        BLUE,
        title,
        RESET,
        width = width
    );
    println!("{}{}├{}┤{}", BOLD, BLUE, "─".repeat(width), RESET);

    for (key, val) in items {
        println!(
            "{}{}│  {}{:<width_k$}{}  {:<width_v$}  │{}",
            BOLD,
            BLUE,
            WHITE,
            key,
            DIM,
            val,
            RESET,
            width_k = max_key,
            width_v = max_val,
        );
    }

    println!("{}{}└{}┘{}", BOLD, BLUE, "─".repeat(width), RESET);
}

pub fn print_status_line(status: &str, msg: &str) {
    let (color, icon) = match status {
        "ok" | "success" | "pass" => (GREEN, "✓"),
        "error" | "fail" => (RED, "✗"),
        "warn" | "warning" => (YELLOW, "⚠"),
        "info" => (CYAN, "ℹ"),
        "running" | "active" => (MAGENTA, "⟳"),
        _ => (WHITE, "•"),
    };
    print!("\r  {}{} {}{} ", color, icon, msg, RESET);
    let _ = io::stdout().flush();
}

pub fn print_completed(status: &str, msg: &str) {
    let (color, icon) = match status {
        "ok" | "success" | "pass" => (GREEN, "✓"),
        "error" | "fail" => (RED, "✗"),
        "warn" | "warning" => (YELLOW, "⚠"),
        _ => (WHITE, "•"),
    };
    println!("  {}{} {}{}", color, icon, msg, RESET);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_colors() {
        assert_eq!(severity_color("Critical"), RED);
        assert_eq!(severity_color("HIGH"), YELLOW);
        assert_eq!(severity_color("Medium"), BLUE);
        assert_eq!(severity_color("low"), CYAN);
        assert_eq!(severity_color("info"), DIM);
    }

    #[test]
    fn test_print_finding() {
        print_finding(1, "Test Finding", "High", Some("Detail line 1\nDetail line 2"));
    }

    #[test]
    fn test_print_summary_box() {
        print_summary_box(
            "Test Summary",
            &[
                ("Total", "100"),
                ("Passed", "80"),
                ("Failed", "20"),
            ],
        );
    }

    #[test]
    fn test_print_table() {
        print_table(
            &["Name", "Status", "Score"],
            &[
                vec!["Tool A", "Active", "95"],
                vec!["Tool B", "Inactive", "72"],
            ],
        );
    }

    #[test]
    fn test_print_banner() {
        print_banner();
    }

    #[test]
    fn test_print_section() {
        print_section("Test Section");
    }

    #[test]
    fn test_print_kv() {
        print_kv("Target", "192.168.1.0/24");
    }
}