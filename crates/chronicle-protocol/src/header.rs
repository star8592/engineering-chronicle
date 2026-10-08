//! Versioned header candidates. Successful parsing establishes syntax only.
use crate::{Counter, Identifier, Sha256Digest, SourcePosition, StatementHeader, ValidationError};
use serde_json::{Map, Value};
use std::fmt;

/// Experimental header schema; this is not a signed Statement envelope.
pub const SCHEMA: &str = "ec.statement-header.v0.1";

/// Immutable validated input, deliberately distinct from an authorized statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderCandidate {
    header: StatementHeader,
    canonical: Vec<u8>,
}

#[derive(Debug)]
pub enum HeaderError {
    Encoding(crate::json::JsonError),
    Shape(&'static str),
    UnsupportedSchema,
    Field {
        field: &'static str,
        error: ValidationError,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(f, "{error}"),
            Self::Shape(field) => write!(f, "header 字段或类型不符合协议：{field}"),
            Self::UnsupportedSchema => f.write_str("不支持的 header schema"),
            Self::Field { field, error } => write!(f, "{field}：{error}"),
        }
    }
}

impl std::error::Error for HeaderError {}

fn object<'a>(
    value: &'a Value,
    fields: &[&str],
    label: &'static str,
) -> Result<&'a Map<String, Value>, HeaderError> {
    let map = value.as_object().ok_or(HeaderError::Shape(label))?;
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err(HeaderError::Shape(label));
    }
    Ok(map)
}

fn string<'a>(map: &'a Map<String, Value>, key: &'static str) -> Result<&'a str, HeaderError> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or(HeaderError::Shape(key))
}

fn identifier(map: &Map<String, Value>, key: &'static str) -> Result<Identifier, HeaderError> {
    Identifier::parse(string(map, key)?).map_err(|error| HeaderError::Field { field: key, error })
}

impl HeaderCandidate {
    /// Reject malformed encoding before using a generic JSON map (which overwrites duplicates).
    pub fn parse(input: &[u8]) -> Result<Self, HeaderError> {
        let canonical = crate::json::canonicalize(input).map_err(HeaderError::Encoding)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| HeaderError::Shape("header"))?;
        let map = object(
            &value,
            &["schema", "project", "position", "kind", "subject"],
            "header",
        )?;
        if string(map, "schema")? != SCHEMA {
            return Err(HeaderError::UnsupportedSchema);
        }
        let position = object(
            &map["position"],
            &["source", "epoch", "sequence"],
            "position",
        )?;
        let header = StatementHeader {
            project: identifier(map, "project")?,
            position: SourcePosition {
                source: identifier(position, "source")?,
                epoch: identifier(position, "epoch")?,
                sequence: Counter::parse(string(position, "sequence")?).map_err(|error| {
                    HeaderError::Field {
                        field: "sequence",
                        error,
                    }
                })?,
            },
            kind: identifier(map, "kind")?,
            subject: Sha256Digest::parse(string(map, "subject")?).map_err(|error| {
                HeaderError::Field {
                    field: "subject",
                    error,
                }
            })?,
        };
        Ok(Self { header, canonical })
    }

    pub fn header(&self) -> &StatementHeader {
        &self.header
    }
    /// Exact bytes for this header only, not signature input for a future full envelope.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        serde_json::json!({
            "schema": SCHEMA, "project": "p1",
            "position": {"source": "ci1", "epoch": "e1", "sequence": "9007199254740993"},
            "kind": "test.failed", "subject": format!("sha256:{}", "a".repeat(64))
        })
    }
    fn parse(value: &Value) -> Result<HeaderCandidate, HeaderError> {
        HeaderCandidate::parse(&serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn valid_header_preserves_counter_and_canonical_bytes() {
        let candidate = parse(&fixture()).unwrap();
        assert_eq!(
            candidate.header().position.sequence.value(),
            9_007_199_254_740_993
        );
        assert_eq!(
            HeaderCandidate::parse(candidate.canonical_bytes()).unwrap(),
            candidate
        );
    }

    #[test]
    fn every_root_field_is_required_and_unknown_fields_rejected() {
        for field in ["schema", "project", "position", "kind", "subject"] {
            let mut value = fixture();
            value.as_object_mut().unwrap().remove(field);
            assert!(matches!(parse(&value), Err(HeaderError::Shape("header"))));
        }
        for field in ["signature", "receipt", "authorized", "extensions"] {
            let mut value = fixture();
            value[field] = Value::Bool(true);
            assert!(matches!(parse(&value), Err(HeaderError::Shape("header"))));
        }
    }

    #[test]
    fn position_is_closed_and_all_fields_required() {
        for field in ["source", "epoch", "sequence"] {
            let mut value = fixture();
            value["position"].as_object_mut().unwrap().remove(field);
            assert!(matches!(parse(&value), Err(HeaderError::Shape("position"))));
        }
        let mut value = fixture();
        value["position"]["extra"] = Value::Null;
        assert!(matches!(parse(&value), Err(HeaderError::Shape("position"))));
    }

    #[test]
    fn rejects_wrong_types_without_coercion() {
        for field in ["schema", "project", "kind", "subject"] {
            for bad in [
                Value::Null,
                Value::Bool(false),
                serde_json::json!([]),
                serde_json::json!({}),
            ] {
                let mut value = fixture();
                value[field] = bad;
                assert!(matches!(parse(&value), Err(HeaderError::Shape(_))));
            }
        }
        for field in ["source", "epoch", "sequence"] {
            let mut value = fixture();
            value["position"][field] = Value::Null;
            assert!(matches!(parse(&value), Err(HeaderError::Shape(_))));
        }
        let mut value = fixture();
        value["position"] = Value::String("source".into());
        assert!(matches!(parse(&value), Err(HeaderError::Shape("position"))));
    }

    #[test]
    fn rejects_unknown_schema_and_invalid_primitives() {
        let mut value = fixture();
        value["schema"] = Value::String("ec.statement-header.v9".into());
        assert!(matches!(parse(&value), Err(HeaderError::UnsupportedSchema)));
        for field in ["project", "kind"] {
            let mut value = fixture();
            value[field] = Value::String("../bad".into());
            assert!(matches!(parse(&value), Err(HeaderError::Field { .. })));
        }
        for field in ["source", "epoch", "sequence"] {
            let mut value = fixture();
            value["position"][field] = Value::String("01/".into());
            assert!(matches!(parse(&value), Err(HeaderError::Field { .. })));
        }
        let mut value = fixture();
        value["subject"] = Value::String("sha256:BAD".into());
        assert!(matches!(parse(&value), Err(HeaderError::Field { .. })));
    }

    #[test]
    fn duplicate_keys_rejected_before_map_construction() {
        let input = serde_json::to_string(&fixture()).unwrap();
        let bad = input.replacen("{", "{\"project\":\"attacker\",", 1);
        assert!(matches!(
            HeaderCandidate::parse(bad.as_bytes()),
            Err(HeaderError::Encoding(_))
        ));
        let bad = input.replacen("\"sequence\":", "\"sequence\":\"0\",\"sequence\":", 1);
        assert!(matches!(
            HeaderCandidate::parse(bad.as_bytes()),
            Err(HeaderError::Encoding(_))
        ));
    }

    #[test]
    fn numeric_tokens_and_counter_overflow_rejected() {
        let mut value = fixture();
        value["position"]["sequence"] = serde_json::json!(1);
        assert!(matches!(parse(&value), Err(HeaderError::Encoding(_))));
        for bad in ["01", "18446744073709551616", "-1"] {
            value["position"]["sequence"] = Value::String(bad.into());
            assert!(matches!(
                parse(&value),
                Err(HeaderError::Field {
                    field: "sequence",
                    ..
                })
            ));
        }
    }
}
