//! Certificate validity times (UTCTime / GeneralizedTime, UTC only).

use super::der::{self, tag, Tlv};
use super::error::{der_err, Result};
use std::time::{SystemTime, UNIX_EPOCH};

/// A point in time, as seconds since 1970-01-01T00:00:00Z.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(pub i64);

/// Days since 1970-01-01 for a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl Time {
    pub fn now() -> Time {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        Time(secs)
    }

    /// `None` when a field is out of range.
    pub fn from_ymd_hms(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<Time> {
        if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || !(0..24).contains(&h) || !(0..60).contains(&mi)
            || !(0..61).contains(&s)
        {
            return None;
        }
        let days = days_from_civil(y, mo, d);
        if civil_from_days(days) != (y, mo, d) {
            return None;
        }
        Some(Time(days * 86_400 + h * 3600 + mi * 60 + s))
    }

    pub fn ymd_hms(&self) -> (i64, i64, i64, i64, i64, i64) {
        let days = self.0.div_euclid(86_400);
        let secs = self.0.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (y, m, d, secs / 3600, secs % 3600 / 60, secs % 60)
    }

    pub fn plus_days(&self, days: i64) -> Time {
        Time(self.0 + days * 86_400)
    }

    /// `YYYY-MM-DD`
    pub fn date_string(&self) -> String {
        let (y, m, d, ..) = self.ymd_hms();
        format!("{y:04}-{m:02}-{d:02}")
    }

    /// DER encoding: UTCTime for 1950..=2049, GeneralizedTime otherwise.
    pub fn to_der(&self) -> Vec<u8> {
        let (y, m, d, h, mi, s) = self.ymd_hms();
        if (1950..2050).contains(&y) {
            der::tlv(tag::UTC_TIME, format!("{:02}{m:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100).as_bytes())
        } else {
            der::tlv(tag::GENERALIZED_TIME, format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes())
        }
    }

    pub fn from_der(t: &Tlv<'_>) -> Result<Time> {
        let text = std::str::from_utf8(t.value).or_else(|_| der_err("time is not ASCII"))?;
        let digits = |s: &str| -> Result<i64> {
            if s.bytes().all(|b| b.is_ascii_digit()) {
                Ok(s.parse().unwrap_or(0))
            } else {
                der_err("non-digit in time")
            }
        };
        let (y, rest) = match t.tag {
            tag::UTC_TIME if text.len() == 13 => {
                let yy = digits(&text[..2])?;
                (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
            }
            tag::GENERALIZED_TIME if text.len() == 15 => (digits(&text[..4])?, &text[4..]),
            _ => return der_err("unsupported time encoding"),
        };
        if !rest.ends_with('Z') {
            return der_err("time is not UTC");
        }
        Time::from_ymd_hms(
            y,
            digits(&rest[0..2])?,
            digits(&rest[2..4])?,
            digits(&rest[4..6])?,
            digits(&rest[6..8])?,
            digits(&rest[8..10])?,
        )
        .ok_or_else(|| super::error::PkiError::Der("time out of range".into()))
    }
}

impl std::fmt::Display for Time {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (y, m, d, h, mi, s) = self.ymd_hms();
        write!(f, "{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_conversions() {
        assert_eq!(Time(0).ymd_hms(), (1970, 1, 1, 0, 0, 0));
        let t = Time::from_ymd_hms(2026, 11, 25, 13, 5, 9).unwrap();
        assert_eq!(t.ymd_hms(), (2026, 11, 25, 13, 5, 9));
        assert_eq!(t.0, 1_795_611_909);
        assert!(Time::from_ymd_hms(2025, 2, 29, 0, 0, 0).is_none());
        assert!(Time::from_ymd_hms(2024, 2, 29, 0, 0, 0).is_some());
        assert_eq!(Time::from_ymd_hms(1969, 12, 31, 23, 59, 59).unwrap().0, -1);
    }

    #[test]
    fn der_forms() {
        let t = Time::from_ymd_hms(2030, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(t.to_der(), [&[0x17, 13][..], b"300102030405Z"].concat());
        let far = Time::from_ymd_hms(2060, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(far.to_der()[0], 0x18);
        for t in [t, far, Time::from_ymd_hms(1999, 12, 31, 23, 59, 59).unwrap()] {
            let enc = t.to_der();
            assert_eq!(Time::from_der(&der::parse_single(&enc).unwrap()).unwrap(), t);
        }
    }
}
