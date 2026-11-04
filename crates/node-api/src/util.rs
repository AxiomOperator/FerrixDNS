use std::time::{Duration, SystemTime};

use crate::error::ApiError;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Formats a millisecond timestamp as UTC ISO 8601.
pub fn to_iso(ms: i64) -> String {
    let millis = u64::try_from(ms).unwrap_or(0);
    let time = SystemTime::UNIX_EPOCH + Duration::from_millis(millis);
    humantime::format_rfc3339_millis(time).to_string()
}

/// Parses a UTC ISO 8601 timestamp into milliseconds.
pub fn from_iso(value: &str) -> Option<i64> {
    let time = humantime::parse_rfc3339_weak(value).ok()?;
    let millis = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()?
        .as_millis();
    i64::try_from(millis).ok()
}

/// Validates an optional timestamp from a request, normalizing it for the policy document.
pub fn normalize_expiry(value: Option<String>) -> Result<Option<String>, ApiError> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| {
            let time = humantime::parse_rfc3339_weak(&value).map_err(|_| {
                ApiError::invalid(
                    "EXPIRY_INVALID",
                    "Use a UTC time such as 2026-12-01T00:00:00Z",
                )
            })?;
            Ok(humantime::format_rfc3339_seconds(time).to_string())
        })
        .transpose()
}
