//! One error type for the whole wallet.
//!
//! Failures used to be plain `String`s, so a caller could only tell "not enough
//! funds" from "the server is down" by matching prose, and every failure exited
//! with the same status. The kind now travels with the message: the shell turns
//! it into an exit status and `--json` prints it as a stable code.
//!
//! Nothing here inspects or formats secret material: messages are the same ones
//! the wallet already showed, only typed.

use std::fmt;

/// What kind of failure this is. The set is deliberately small: each kind has a
/// different remedy for the person or script on the other end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Something the user supplied is invalid: an address, amount, path, flag.
    /// Repeating the command with corrected input fixes it.
    Input,
    /// Local state could not be used: wallet file, keystore, filesystem.
    State,
    /// The backend could not be reached, or answered something unusable.
    /// Another endpoint or a later retry may work.
    Network,
    /// The backend refused the request outright (a rejected transaction, a
    /// definitive HTTP 4xx). Retrying elsewhere is pointless.
    Rejected,
    /// Not classified yet; carries the message unchanged.
    Other,
}

/// A failure, with the kind of failure attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    kind: Kind,
    message: String,
}

impl Error {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn input(message: impl Into<String>) -> Self {
        Self::new(Kind::Input, message)
    }

    pub fn state(message: impl Into<String>) -> Self {
        Self::new(Kind::State, message)
    }

    pub fn network(message: impl Into<String>) -> Self {
        Self::new(Kind::Network, message)
    }

    pub fn rejected(message: impl Into<String>) -> Self {
        Self::new(Kind::Rejected, message)
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    /// Stable identifier for machine-readable output. These strings are part of
    /// the `--json` contract; add new ones, never rename an existing one.
    pub fn code(&self) -> &'static str {
        match self.kind {
            Kind::Input => "input",
            Kind::State => "state",
            Kind::Network => "network",
            Kind::Rejected => "rejected",
            Kind::Other => "error",
        }
    }

    /// Process exit status: scripts can tell a bad invocation from a server that
    /// was down without parsing the message.
    pub fn exit_code(&self) -> i32 {
        match self.kind {
            Kind::Input => 2,
            Kind::State => 1,
            Kind::Network => 4,
            Kind::Rejected => 3,
            Kind::Other => 1,
        }
    }

    /// True when the message contains `needle`. Tests assert on what the user
    /// reads, so this keeps those assertions readable now that the error is a
    /// type instead of a `String`.
    #[cfg(test)]
    pub fn contains(&self, needle: &str) -> bool {
        self.message.contains(needle)
    }

    /// Re-label an unclassified error, keeping its message. Used at the few
    /// places that know more about a failure than the code that produced it.
    pub fn as_kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// An unclassified message becomes `Kind::Other` so the conversion is a no-op
/// for code that has not been classified yet.
impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::new(Kind::Other, message)
    }
}

impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::new(Kind::Other, message)
    }
}

/// Lets `?` keep working in the few places that still build a `String` (help
/// text, tests) while the rest of the crate speaks `Error`.
impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.message
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_the_message_unchanged() {
        let e = Error::network("connection refused");
        assert_eq!(e.to_string(), "connection refused");
        assert_eq!(e.message(), "connection refused");
    }

    #[test]
    fn json_codes_and_exit_statuses_are_stable() {
        assert_eq!(Error::input("x").code(), "input");
        assert_eq!(Error::state("x").code(), "state");
        assert_eq!(Error::network("x").code(), "network");
        assert_eq!(Error::rejected("x").code(), "rejected");
        assert_eq!(Error::from("x".to_string()).code(), "error");

        assert_eq!(Error::input("x").exit_code(), 2);
        assert_eq!(Error::rejected("x").exit_code(), 3);
        assert_eq!(Error::network("x").exit_code(), 4);
    }

    #[test]
    fn unclassified_strings_keep_their_text() {
        let e: Error = "wallet file is locked".to_string().into();
        assert_eq!(e.kind(), Kind::Other);
        assert_eq!(e.to_string(), "wallet file is locked");
        let back: String = e.into();
        assert_eq!(back, "wallet file is locked");
    }

    #[test]
    fn relabelling_keeps_the_message() {
        let e = Error::from("HTTP 500").as_kind(Kind::Network);
        assert_eq!(e.code(), "network");
        assert_eq!(e.to_string(), "HTTP 500");
    }
}
