use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RedactionLevel {
    Full = 0,    // "[REDACTED]" (default, current behavior)
    Partial = 1, // first 4 chars + "..."
    None = 2,    // show the value (for local debugging only)
}

static LEVEL: AtomicU8 = AtomicU8::new(0);

pub fn set_redaction_level(level: RedactionLevel) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

pub fn redaction_level() -> RedactionLevel {
    match LEVEL.load(Ordering::Relaxed) {
        1 => RedactionLevel::Partial,
        2 => RedactionLevel::None,
        _ => RedactionLevel::Full,
    }
}

pub fn redact(value: &str) -> String {
    match redaction_level() {
        RedactionLevel::Full => "[REDACTED]".into(),
        RedactionLevel::Partial => {
            let mut chars = value.chars();
            let prefix: String = chars.by_ref().take(4).collect();
            if prefix.chars().count() < 4 || chars.next().is_none() {
                "[REDACTED]".into()
            } else {
                format!("{prefix}...")
            }
        }
        RedactionLevel::None => value.into(),
    }
}

/// Render a value's `Debug` through the active redaction level
pub(crate) fn redacted_debug(value: &impl fmt::Debug) -> String {
    redact(&format!("{value:?}"))
}
