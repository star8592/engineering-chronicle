//! Restricted JCS-compatible JSON subset: no numeric tokens, object root.
//! Encoding does not establish schema validity, authorization or authenticity.
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use std::{collections::HashSet, fmt};

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonError {
    TooLarge,
    TooDeep,
    DuplicateKey,
    NumericToken,
    InvalidJson,
    ObjectRequired,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "JSON 输入超过 1 MiB",
            Self::TooDeep => "JSON 节点深度超过 32",
            Self::DuplicateKey => "JSON 包含重复字段",
            Self::NumericToken => "协议不允许 JSON 数值，必须使用规范字符串",
            Self::InvalidJson => "JSON 格式或 Unicode 数据无效",
            Self::ObjectRequired => "协议 JSON 根必须是对象",
        })
    }
}
impl std::error::Error for JsonError {}

enum Value {
    Null,
    Bool(bool),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}
struct Seed(usize);

impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Value, D::Error> {
        if self.0 > MAX_DEPTH {
            return Err(D::Error::custom("EC_DEPTH"));
        }
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("restricted protocol JSON")
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_i64<E: Error>(self, _: i64) -> Result<Value, E> {
        Err(E::custom("EC_NUMBER"))
    }
    fn visit_u64<E: Error>(self, _: u64) -> Result<Value, E> {
        Err(E::custom("EC_NUMBER"))
    }
    fn visit_f64<E: Error>(self, _: f64) -> Result<Value, E> {
        Err(E::custom("EC_NUMBER"))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed(self.0 + 1))? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut keys = HashSet::new();
        let mut entries = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom("EC_DUPLICATE"));
            }
            entries.push((key, map.next_value_seed(Seed(self.0 + 1))?));
        }
        Ok(Value::Object(entries))
    }
}

fn classify(error: serde_json::Error) -> JsonError {
    let message = error.to_string();
    if message.starts_with("EC_DEPTH") {
        JsonError::TooDeep
    } else if message.starts_with("EC_DUPLICATE") {
        JsonError::DuplicateKey
    } else if message.starts_with("EC_NUMBER") {
        JsonError::NumericToken
    } else {
        JsonError::InvalidJson
    }
}

/// Validate raw input before constructing a map that could discard duplicate keys.
/// Returns exact canonical bytes without a trailing newline.
/// Supports strings, null, booleans, arrays and objects; all numeric tokens rejected.
/// Root depth is zero, each value edge increments depth, maximum node depth is 32.
pub fn canonicalize(input: &[u8]) -> Result<Vec<u8>, JsonError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(JsonError::TooLarge);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = Seed(0).deserialize(&mut deserializer).map_err(classify)?;
    deserializer.end().map_err(classify)?;
    if !matches!(value, Value::Object(_)) {
        return Err(JsonError::ObjectRequired);
    }
    let mut output = Vec::new();
    encode(&value, &mut output)?;
    Ok(output)
}

fn encode(value: &Value, output: &mut Vec<u8>) -> Result<(), JsonError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::String(text) => {
            serde_json::to_writer(output, text).map_err(|_| JsonError::InvalidJson)?
        }
        Value::Array(values) => {
            output.push(b'[');
            for (i, item) in values.iter().enumerate() {
                if i != 0 {
                    output.push(b',');
                }
                encode(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(entries) => {
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            output.push(b'{');
            for (i, (key, item)) in sorted.into_iter().enumerate() {
                if i != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|_| JsonError::InvalidJson)?;
                output.push(b':');
                encode(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_recursive_objects_and_preserves_array_order() {
        assert_eq!(
            canonicalize(br#" { "z": [false, null, {"b":"2","a":"1"}], "a":true } "#).unwrap(),
            br#"{"a":true,"z":[false,null,{"a":"1","b":"2"}]}"#
        );
    }
    #[test]
    fn rejects_decoded_duplicate_keys_at_any_level() {
        for input in [
            br#"{"a":true,"a":false}"#.as_slice(),
            br#"{"a":true,"\u0061":false}"#,
            br#"{"x":[{"a":null,"a":null}]}"#,
        ] {
            assert_eq!(canonicalize(input), Err(JsonError::DuplicateKey));
        }
    }
    #[test]
    fn rejects_numeric_tokens_including_negative_zero() {
        for number in ["0", "-0", "1", "1.0", "1e2", "9007199254740993"] {
            assert_eq!(
                canonicalize(format!(r#"{{"n":{number}}}"#).as_bytes()),
                Err(JsonError::NumericToken)
            );
        }
    }
    #[test]
    fn rejects_lone_surrogates_invalid_utf8_and_trailing_data() {
        for input in [
            br#"{"s":"\ud800"}"#.as_slice(),
            br#"{"s":"\udfff"}"#,
            b"{\"s\":\"\xff\"}",
            br#"{} {}"#,
            br#"{"a":true,}"#,
        ] {
            assert_eq!(canonicalize(input), Err(JsonError::InvalidJson));
        }
    }
    #[test]
    fn accepts_valid_surrogate_pair_without_normalizing_unicode() {
        assert_eq!(
            canonicalize(br#"{"s":"\ud83d\ude00"}"#).unwrap(),
            "{\"s\":\"😀\"}".as_bytes()
        );
        assert_ne!(
            canonicalize("{\"s\":\"é\"}".as_bytes()).unwrap(),
            canonicalize("{\"s\":\"é\"}".as_bytes()).unwrap()
        );
    }
    #[test]
    fn follows_rfc_property_order_in_utf16_not_utf8() {
        let input = "{\"דּ\":null,\"😀\":null,\"€\":null,\"ö\":null,\"\u{80}\":null,\"1\":null,\"\\r\":null}";
        let expected = "{\"\\r\":null,\"1\":null,\"\u{80}\":null,\"ö\":null,\"€\":null,\"😀\":null,\"דּ\":null}";
        assert_eq!(canonicalize(input.as_bytes()).unwrap(), expected.as_bytes());
    }
    #[test]
    fn emits_canonical_string_escapes() {
        assert_eq!(
            canonicalize(br#"{"s":"\u000f\b\t\n\f\r\/\u2028"}"#).unwrap(),
            "{\"s\":\"\\u000f\\b\\t\\n\\f\\r/\u{2028}\"}".as_bytes()
        );
    }
    #[test]
    fn depth_boundary_is_enforced_during_parsing() {
        fn nested(arrays: usize) -> Vec<u8> {
            format!("{{\"a\":{}null{}}}", "[".repeat(arrays), "]".repeat(arrays)).into_bytes()
        }
        assert!(canonicalize(&nested(MAX_DEPTH - 1)).is_ok());
        assert_eq!(canonicalize(&nested(MAX_DEPTH)), Err(JsonError::TooDeep));
    }
    #[test]
    fn size_boundary_is_enforced_before_parsing() {
        let allowed = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_INPUT_BYTES - 8));
        assert_eq!(allowed.len(), MAX_INPUT_BYTES);
        assert!(canonicalize(allowed.as_bytes()).is_ok());
        assert_eq!(
            canonicalize(&vec![b' '; MAX_INPUT_BYTES + 1]),
            Err(JsonError::TooLarge)
        );
    }
    #[test]
    fn refuses_non_object_roots() {
        for input in [b"null".as_slice(), b"true", b"\"text\"", b"[]"] {
            assert_eq!(canonicalize(input), Err(JsonError::ObjectRequired));
        }
    }
    #[test]
    fn canonicalization_is_idempotent() {
        let once = canonicalize(br#"{"z":"\u0061","a":{"c":null,"b":true}}"#).unwrap();
        assert_eq!(canonicalize(&once).unwrap(), once);
    }
}
