//! Shared ANSI color constants and formatting helpers for terminal output.

use std::time::{SystemTime, UNIX_EPOCH};

pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const YELLOW: &str = "\x1b[33m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RESET: &str = "\x1b[0m";

/// Format a unix epoch timestamp as a human-readable UTC string.
pub fn format_epoch(epoch: u64) -> String {
    let days = epoch / 86400;
    let time_of_day = epoch % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_date(days);

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02} UTC")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm from Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Format milliseconds as a human-readable duration.
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        #[allow(clippy::cast_precision_loss)]
        let secs = ms as f64 / 1000.0;
        format!("{secs:.1}s")
    } else {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        format!("{mins}m {secs}s")
    }
}

/// Format a relative time description (e.g., "2 hours ago").
pub fn format_relative(epoch: u64) -> String {
    let now = now_epoch();
    if epoch > now {
        return "just now".to_string();
    }
    let delta = now - epoch;
    if delta < 60 {
        return "just now".to_string();
    }
    if delta < 3600 {
        let mins = delta / 60;
        return if mins == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{mins} minutes ago")
        };
    }
    if delta < 86400 {
        let hours = delta / 3600;
        return if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{hours} hours ago")
        };
    }
    let days = delta / 86400;
    if days == 1 {
        "1 day ago".to_string()
    } else {
        format!("{days} days ago")
    }
}

/// Format a byte count as a human-readable size.
#[allow(clippy::cast_precision_loss)]
pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

const SPARK_CHARS: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Maximum number of data points to display in a sparkline.
const SPARK_MAX_WIDTH: usize = 30;

/// Render a sparkline string from a slice of u64 values.
/// If the input has more than `SPARK_MAX_WIDTH` points, the tail is used.
/// Returns an empty string if the input is empty.
pub fn sparkline(values: &[u64]) -> String {
    if values.is_empty() {
        return String::new();
    }
    let values = if values.len() > SPARK_MAX_WIDTH {
        &values[values.len() - SPARK_MAX_WIDTH..]
    } else {
        values
    };
    let max = *values.iter().max().unwrap_or(&0);
    if max == 0 {
        return SPARK_CHARS[0].to_string().repeat(values.len());
    }
    values
        .iter()
        .map(|&v| {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let idx = ((v as f64 / max as f64) * (SPARK_CHARS.len() - 1) as f64).round() as usize;
            SPARK_CHARS[idx.min(SPARK_CHARS.len() - 1)]
        })
        .collect()
}

/// Current time as seconds since the Unix epoch.
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_epoch_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(format_epoch(1_704_067_200), "2024-01-01 00:00:00 UTC");
    }

    #[test]
    fn format_duration_millis() {
        assert_eq!(format_duration_ms(42), "42ms");
        assert_eq!(format_duration_ms(1500), "1.5s");
        assert_eq!(format_duration_ms(125_000), "2m 5s");
    }

    #[test]
    fn format_bytes_ranges() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn sparkline_empty() {
        assert_eq!(sparkline(&[]), "");
    }

    #[test]
    fn sparkline_all_zeros() {
        assert_eq!(sparkline(&[0, 0, 0]), "▁▁▁");
    }

    #[test]
    fn sparkline_range() {
        let s = sparkline(&[0, 50, 100]);
        assert_eq!(s, "▁▅█");
    }

    #[test]
    fn sparkline_single_value() {
        assert_eq!(sparkline(&[42]), "█");
    }
}
