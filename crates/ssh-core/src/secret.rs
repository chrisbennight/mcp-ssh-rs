//! A wrapper for values that must not be printed.
//!
//! The service holds credentials for every target it can reach, and the most
//! likely way one escapes is not an attack but a debug print, a log line, or an
//! error that interpolated a struct. This makes that mistake fail to compile
//! rather than fail in production: the inner value cannot be reached without
//! writing [`Secret::expose`], which is greppable in review.

use std::fmt;

/// Holds a value whose contents must not appear in output.
///
/// `Debug` is implemented to redact. `Display` deliberately is not implemented
/// at all, so a secret cannot be interpolated into a string, a log message, or
/// an error by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Yields the protected value.
    ///
    /// Named so that every place a secret leaves its wrapper is findable with a
    /// single search, which is the point of the type.
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// The realistic leak is a struct printed whole — a tracing field, an
    /// `anyhow` context, a derived `Debug` on something that holds a secret.
    /// If this ever passes the value through, credentials reach logs.
    #[test]
    fn debug_output_never_contains_the_value() {
        let secret = Secret::new("hunter2-correct-horse".to_owned());
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");

        // Fields are read only by the derived `Debug`, which is the whole
        // point: this reproduces a struct being printed whole.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Holder {
            name: &'static str,
            credential: Secret<String>,
        }
        let rendered = format!(
            "{:?}",
            Holder {
                name: "dns1",
                credential: Secret::new("hunter2-correct-horse".to_owned()),
            }
        );
        assert!(rendered.contains("dns1"), "non-secret fields still render");
        assert!(!rendered.contains("hunter2"), "secret leaked: {rendered}");
    }

    #[test]
    fn exposing_yields_the_value() {
        let secret = Secret::new(vec![1_u8, 2, 3]);
        assert_eq!(secret.expose(), &[1, 2, 3]);
    }
}
