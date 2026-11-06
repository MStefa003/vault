//! Minimal UTC time helpers (avoids pulling in a date/time dependency).

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Convert days since 1970-01-01 to a civil (year, month, day) date.
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Days since 1970-01-01 for a civil date (Hinnant's `days_from_civil`).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DDTHH:MM:SS[Z]` (UTC) into unix seconds.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = s.split_once('T').unwrap_or((s, "00:00:00"));
    let mut d = date.splitn(3, '-').map(|p| p.parse::<i64>().ok());
    let (y, mo, da) = (d.next()??, d.next()??, d.next()??);
    let mut t = time
        .splitn(3, ':')
        .map(|p| p.split('.').next()?.parse::<i64>().ok());
    let (h, mi, se) = (
        t.next().flatten().unwrap_or(0),
        t.next().flatten().unwrap_or(0),
        t.next().flatten().unwrap_or(0),
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo as u32, da as u32) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Format a unix timestamp as `YYYY-MM-DD` (UTC).
pub fn format_date(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM UTC`.
pub fn format_datetime(ts: i64) -> String {
    let secs = ts.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02} UTC",
        format_date(ts),
        secs / 3600,
        (secs % 3600) / 60
    )
}

/// Compact timestamp for file names: `YYYYMMDD-HHMMSS`.
pub fn file_stamp(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(86_400));
    let secs = ts.rem_euclid(86_400);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Human readable "time ago" for a past timestamp.
pub fn age_description(ts: i64, now: i64) -> String {
    let days = (now - ts).max(0) / 86_400;
    match days {
        0 => crate::i18n::tr("today").into(),
        1 => crate::i18n::tr("yesterday").into(),
        2..=59 => crate::trf!("{days} days ago", days),
        60..=729 => crate::trf!("{} months ago", days / 30),
        _ => crate::trf!("{} years ago", days / 365),
    }
}

/// "Expires in 5 days", "Expires today", "Expired 3 days ago".
pub fn expiry_description(at: i64, now: i64) -> String {
    if at <= now {
        return crate::trf!("Expired {}", age_description(at, now));
    }
    let days = (at - now) / 86_400;
    match days {
        0 => crate::i18n::tr("Expires today").into(),
        1 => crate::i18n::tr("Expires tomorrow").into(),
        2..=59 => crate::trf!("Expires in {days} days", days),
        60..=729 => crate::trf!("Expires in {} months", days / 30),
        _ => crate::trf!("Expires {}", format_date(at)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(951_782_400), "2000-02-29");
        assert_eq!(format_datetime(1_700_000_000), "2023-11-14 22:13 UTC");
        assert_eq!(file_stamp(1_700_000_000), "20231114-221320");
    }

    #[test]
    fn expiry_descriptions() {
        let now = 1_700_000_000;
        assert_eq!(
            expiry_description(now + 3 * 86_400, now),
            "Expires in 3 days"
        );
        assert_eq!(expiry_description(now + 100, now), "Expires today");
        assert_eq!(expiry_description(now + 86_400, now), "Expires tomorrow");
        assert_eq!(
            expiry_description(now - 2 * 86_400, now),
            "Expired 2 days ago"
        );
    }

    #[test]
    fn civil_roundtrip_and_iso_parsing() {
        for days in [-1000, 0, 1, 11_016, 19_675, 50_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(parse_iso8601("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(parse_iso8601("1970-01-01T00:00:00"), Some(0));
        assert_eq!(parse_iso8601("2000-02-29"), Some(951_782_400));
        assert_eq!(parse_iso8601("2023-13-01T00:00:00Z"), None);
        assert_eq!(parse_iso8601("garbage"), None);
    }
}
