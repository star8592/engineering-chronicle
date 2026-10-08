//! Validated protocol primitives, restricted encoding and experimental header candidates.
//! Signature matching does not establish source identity or authorization.
//!
//! Parsing establishes syntax only; it never establishes identity or authorization.

pub mod envelope;
pub mod header;
pub mod json;
pub mod signature;

use std::fmt;

/// A bounded, opaque identifier, never a filesystem path.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Identifier(String);

/// A canonical decimal counter with an explicitly bounded unsigned range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Counter(u64);

/// A declared SHA-256 digest; parsing does not hash or verify any asset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha256Digest(String);

/// Identifies one position in a registered source epoch.
/// Registration and authorization are not provided by this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePosition {
    pub source: Identifier,
    pub epoch: Identifier,
    pub sequence: Counter,
}

/// Source record fields must be separated from platform-assigned receipt fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatementHeader {
    pub project: Identifier,
    pub position: SourcePosition,
    pub kind: Identifier,
    pub subject: Sha256Digest,
}

/// A platform-assigned location; this value alone is not proof of acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptPosition {
    pub log: Identifier,
    pub epoch: Identifier,
    pub leaf_index: Counter,
}

/// Syntax errors never collapse into a successful verification status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    IdentifierLength,
    IdentifierCharacters,
    CounterSyntax,
    CounterOverflow,
    DigestSyntax,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::IdentifierLength => "标识长度必须为 1–128 个 ASCII 字节",
            Self::IdentifierCharacters => {
                "标识必须以字母或数字开头，仅允许 ASCII 字母、数字、点、下划线和连字符"
            }
            Self::CounterSyntax => "序号必须为规范无符号十进制字符串，不允许前导零",
            Self::CounterOverflow => "序号超出 u64 范围",
            Self::DigestSyntax => "摘要必须为 sha256: 加 64 位小写十六进制",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ValidationError {}

impl Identifier {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty() || value.len() > 128 {
            return Err(ValidationError::IdentifierLength);
        }
        let bytes = value.as_bytes();
        if !bytes[0].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(ValidationError::IdentifierCharacters);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Counter {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if value.is_empty()
            || !value.bytes().all(|b| b.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(ValidationError::CounterSyntax);
        }
        if value.len() > 20 {
            return Err(ValidationError::CounterOverflow);
        }
        value
            .parse::<u64>()
            .map(Self)
            .map_err(|_| ValidationError::CounterOverflow)
    }

    pub fn value(self) -> u64 {
        self.0
    }

    pub fn checked_next(self) -> Result<Self, ValidationError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ValidationError::CounterOverflow)
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Sha256Digest {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        let hex = value
            .strip_prefix("sha256:")
            .ok_or(ValidationError::DigestSyntax)?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ValidationError::DigestSyntax);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_accepts_bounded_ascii_names() {
        for value in [
            "project-01",
            "runner_1",
            "ci.test.failed",
            "A",
            &"a".repeat(128),
        ] {
            assert_eq!(Identifier::parse(value).unwrap().as_str(), value);
        }
    }

    #[test]
    fn identifier_rejects_paths_unicode_and_control_bytes() {
        for value in [
            "../secret",
            "/tmp",
            ".hidden",
            "来源",
            "a b",
            "a\n",
            "a\0",
            "a/b",
            "a\\b",
        ] {
            assert_eq!(
                Identifier::parse(value),
                Err(ValidationError::IdentifierCharacters),
                "{value:?}"
            );
        }
    }

    #[test]
    fn identifier_rejects_empty_and_oversized_inputs() {
        for value in ["", &"a".repeat(129)] {
            assert_eq!(
                Identifier::parse(value),
                Err(ValidationError::IdentifierLength)
            );
        }
    }

    #[test]
    fn counter_accepts_zero_and_full_unsigned_range_without_rounding() {
        for (input, expected) in [
            ("0", 0),
            ("9007199254740993", 9_007_199_254_740_993),
            ("18446744073709551615", u64::MAX),
        ] {
            let counter = Counter::parse(input).unwrap();
            assert_eq!(counter.value(), expected);
            assert_eq!(counter.to_string(), input);
        }
    }

    #[test]
    fn counter_rejects_ambiguous_numeric_representations() {
        for value in ["", "00", "01", "+1", "-1", "1.0", "1e3", " 1", "1 ", "１"] {
            assert_eq!(
                Counter::parse(value),
                Err(ValidationError::CounterSyntax),
                "{value:?}"
            );
        }
    }

    #[test]
    fn counter_overflow_is_explicit_and_never_wraps() {
        for value in ["18446744073709551616", "999999999999999999999"] {
            assert_eq!(Counter::parse(value), Err(ValidationError::CounterOverflow));
        }
        assert_eq!(
            Counter::parse("18446744073709551615")
                .unwrap()
                .checked_next(),
            Err(ValidationError::CounterOverflow)
        );
        assert_eq!(
            Counter::parse("0").unwrap().checked_next().unwrap().value(),
            1
        );
    }

    #[test]
    fn digest_preserves_exact_declared_value() {
        let value = format!("sha256:{}", "0123456789abcdef".repeat(4));
        assert_eq!(Sha256Digest::parse(&value).unwrap().as_str(), value);
    }

    #[test]
    fn digest_rejects_wrong_algorithm_case_length_and_non_hex() {
        for value in [
            format!("sha512:{}", "a".repeat(64)),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("sha256:{}", "a".repeat(65)),
            format!("sha256:{}", "g".repeat(64)),
            format!("sha256:{}", "é".repeat(32)),
        ] {
            assert_eq!(
                Sha256Digest::parse(&value),
                Err(ValidationError::DigestSyntax),
                "{value:?}"
            );
        }
    }
}
