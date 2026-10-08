//! Experimental DSSE framing for header candidates; no signature verification.
use crate::header::HeaderCandidate;
use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use serde_json::Value;
use std::fmt;

pub const PAYLOAD_TYPE: &str = "application/vnd.engineering-chronicle.statement-header.v0.1+json";
pub const MAX_SIGNATURES: usize = 8;
const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(false);
const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);

/// Signature-shaped bytes. The name deliberately makes no validity claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureCandidate {
    key_hint: Option<crate::Identifier>,
    bytes: [u8; 64],
}
impl SignatureCandidate {
    /// An unauthenticated lookup hint, never a principal or authorization.
    pub fn key_hint(&self) -> Option<&crate::Identifier> {
        self.key_hint.as_ref()
    }
    pub fn bytes(&self) -> &[u8; 64] {
        &self.bytes
    }
}

/// Immutable framing candidate, never proof of identity or authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderEnvelopeCandidate {
    payload: HeaderCandidate,
    signatures: Vec<SignatureCandidate>,
}

#[derive(Debug)]
pub enum EnvelopeError {
    Encoding(crate::json::JsonError),
    Shape,
    PayloadType,
    Base64,
    Header(crate::header::HeaderError),
    NoncanonicalPayload,
    SignatureCount,
    SignatureLength,
    KeyHint,
    PaeLimit,
}
impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(e) => write!(f, "{e}"),
            Self::Header(e) => write!(f, "{e}"),
            _ => f.write_str(match self {
                Self::Shape => "封套字段或类型不符合协议",
                Self::PayloadType => "不支持的载荷类型",
                Self::Base64 => "无效 Base64 编码",
                Self::NoncanonicalPayload => "载荷必须已经是精确规范字节",
                Self::SignatureCount => "签名候选数量必须为 1–8",
                Self::SignatureLength => "Ed25519 签名候选必须为 64 字节",
                Self::KeyHint => "无效密钥提示标识",
                Self::PaeLimit => "待签数据超出大小限制",
                _ => unreachable!(),
            }),
        }
    }
}
impl std::error::Error for EnvelopeError {}

fn decode(input: &str) -> Result<Vec<u8>, EnvelopeError> {
    STANDARD
        .decode(input)
        .or_else(|_| URL_SAFE.decode(input))
        .map_err(|_| EnvelopeError::Base64)
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, EnvelopeError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(EnvelopeError::Shape)
}

/// DSSE v1 Pre-Authentication Encoding; lengths count bytes, not Unicode characters.
/// This helper does not sign, hash or verify anything.
pub fn pre_authentication_encoding(
    payload_type: &str,
    body: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if payload_type.len() > 256 || body.len() > crate::json::MAX_INPUT_BYTES {
        return Err(EnvelopeError::PaeLimit);
    }
    let mut bytes = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    Ok(bytes)
}

impl HeaderEnvelopeCandidate {
    pub fn parse(input: &[u8]) -> Result<Self, EnvelopeError> {
        let canonical = crate::json::canonicalize(input).map_err(EnvelopeError::Encoding)?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|_| EnvelopeError::Shape)?;
        let map = value.as_object().ok_or(EnvelopeError::Shape)?;
        if map.len() != 3
            || !["payloadType", "payload", "signatures"]
                .iter()
                .all(|k| map.contains_key(*k))
        {
            return Err(EnvelopeError::Shape);
        }
        if string(&value, "payloadType")? != PAYLOAD_TYPE {
            return Err(EnvelopeError::PayloadType);
        }
        let raw_payload = decode(string(&value, "payload")?)?;
        let payload = HeaderCandidate::parse(&raw_payload).map_err(EnvelopeError::Header)?;
        // Never substitute reserialized bytes for received bytes in signature verification.
        if payload.canonical_bytes() != raw_payload {
            return Err(EnvelopeError::NoncanonicalPayload);
        }
        let entries = value["signatures"].as_array().ok_or(EnvelopeError::Shape)?;
        if entries.is_empty() || entries.len() > MAX_SIGNATURES {
            return Err(EnvelopeError::SignatureCount);
        }
        let mut signatures = Vec::with_capacity(entries.len());
        for entry in entries {
            let fields = entry.as_object().ok_or(EnvelopeError::Shape)?;
            if !fields.contains_key("sig") || fields.keys().any(|k| k != "sig" && k != "keyid") {
                return Err(EnvelopeError::Shape);
            }
            let key_hint = match entry.get("keyid") {
                None => None,
                Some(Value::String(s)) if s.is_empty() => None,
                Some(Value::String(s)) => {
                    Some(crate::Identifier::parse(s).map_err(|_| EnvelopeError::KeyHint)?)
                }
                Some(_) => return Err(EnvelopeError::Shape),
            };
            let bytes = decode(string(entry, "sig")?)?
                .try_into()
                .map_err(|_| EnvelopeError::SignatureLength)?;
            signatures.push(SignatureCandidate { key_hint, bytes });
        }
        Ok(Self {
            payload,
            signatures,
        })
    }
    pub fn payload(&self) -> &HeaderCandidate {
        &self.payload
    }
    pub fn signatures(&self) -> &[SignatureCandidate] {
        &self.signatures
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        pre_authentication_encoding(PAYLOAD_TYPE, self.payload.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn payload() -> Vec<u8> {
        let value = serde_json::json!({
            "schema": crate::header::SCHEMA, "project": "p1",
            "position": {"source":"ci1","epoch":"e1","sequence":"0"},
            "kind":"test.failed", "subject":format!("sha256:{}", "a".repeat(64))
        });
        crate::json::canonicalize(&serde_json::to_vec(&value).unwrap()).unwrap()
    }
    fn fixture() -> Value {
        serde_json::json!({"payloadType":PAYLOAD_TYPE,"payload":STANDARD.encode(payload()),
            "signatures":[{"keyid":"ci-key","sig":STANDARD.encode([255_u8;64])}]})
    }
    fn parse(value: &Value) -> Result<HeaderEnvelopeCandidate, EnvelopeError> {
        HeaderEnvelopeCandidate::parse(&serde_json::to_vec(value).unwrap())
    }
    #[test]
    fn official_dsse_pae_vector() {
        assert_eq!(
            pre_authentication_encoding("http://example.com/HelloWorld", b"hello world").unwrap(),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }
    #[test]
    fn pae_lengths_are_utf8_bytes_and_preserve_binary_body() {
        assert_eq!(
            pre_authentication_encoding("中", &[0, 255]).unwrap(),
            [b"DSSEv1 3 ".as_slice(), "中".as_bytes(), b" 2 ", &[0, 255]].concat()
        );
        assert_eq!(
            pre_authentication_encoding("", b"").unwrap(),
            b"DSSEv1 0  0 "
        );
    }
    #[test]
    fn valid_candidate_keeps_exact_payload_and_signature_bytes() {
        let candidate = parse(&fixture()).unwrap();
        assert_eq!(candidate.payload().canonical_bytes(), payload());
        assert_eq!(candidate.signatures()[0].bytes(), &[255; 64]);
        assert_eq!(
            candidate.signatures()[0].key_hint().unwrap().as_str(),
            "ci-key"
        );
        assert!(candidate.signing_bytes().unwrap().ends_with(&payload()));
    }
    #[test]
    fn accepts_both_base64_alphabets_with_or_without_padding() {
        for engine in [STANDARD, URL_SAFE] {
            for padding in [true, false] {
                let mut value = fixture();
                let p = engine.encode(payload());
                let sig = engine.encode([255_u8; 64]);
                value["payload"] = Value::String(if padding {
                    p
                } else {
                    p.trim_end_matches('=').into()
                });
                value["signatures"][0]["sig"] = Value::String(if padding {
                    sig
                } else {
                    sig.trim_end_matches('=').into()
                });
                assert!(parse(&value).is_ok());
            }
        }
    }
    #[test]
    fn missing_and_empty_key_hint_are_equivalent_and_do_not_affect_pae() {
        let original = parse(&fixture()).unwrap();
        let mut value = fixture();
        value["signatures"][0]
            .as_object_mut()
            .unwrap()
            .remove("keyid");
        let missing = parse(&value).unwrap();
        value["signatures"][0]["keyid"] = Value::String(String::new());
        assert_eq!(parse(&value).unwrap(), missing);
        assert_eq!(
            original.signing_bytes().unwrap(),
            missing.signing_bytes().unwrap()
        );
        value["signatures"][0]["keyid"] = Value::String("../bad".into());
        assert!(matches!(parse(&value), Err(EnvelopeError::KeyHint)));
    }
    #[test]
    fn refuses_wrong_type_unknown_fields_and_missing_fields() {
        let mut value = fixture();
        value["payloadType"] = Value::String("application/json".into());
        assert!(matches!(parse(&value), Err(EnvelopeError::PayloadType)));
        for field in ["payloadType", "payload", "signatures"] {
            let mut value = fixture();
            value.as_object_mut().unwrap().remove(field);
            assert!(matches!(parse(&value), Err(EnvelopeError::Shape)));
        }
        let mut value = fixture();
        value["trusted"] = Value::Bool(true);
        assert!(matches!(parse(&value), Err(EnvelopeError::Shape)));
        let mut value = fixture();
        value["signatures"][0]["verified"] = Value::Bool(true);
        assert!(matches!(parse(&value), Err(EnvelopeError::Shape)));
        value = fixture();
        value["signatures"][0]["keyid"] = Value::Null;
        assert!(matches!(parse(&value), Err(EnvelopeError::Shape)));
    }
    #[test]
    fn rejects_reencoding_payload_even_when_json_semantics_match() {
        let mut value = fixture();
        value["payload"] = Value::String(STANDARD.encode([b" ".as_slice(), &payload()].concat()));
        assert!(matches!(
            parse(&value),
            Err(EnvelopeError::NoncanonicalPayload)
        ));
    }
    #[test]
    fn rejects_duplicate_keys_in_outer_and_inner_documents() {
        let raw =
            serde_json::to_string(&fixture())
                .unwrap()
                .replacen("{", "{\"payload\":\"x\",", 1);
        assert!(matches!(
            HeaderEnvelopeCandidate::parse(raw.as_bytes()),
            Err(EnvelopeError::Encoding(_))
        ));
        let mut value = fixture();
        let raw =
            String::from_utf8(payload())
                .unwrap()
                .replacen("{", "{\"project\":\"attacker\",", 1);
        value["payload"] = Value::String(STANDARD.encode(raw));
        assert!(matches!(parse(&value), Err(EnvelopeError::Header(_))));
    }
    #[test]
    fn rejects_bad_base64_signature_lengths_and_counts() {
        for bad in ["!", "A", "AB==", "a G==", "////-_=="] {
            let mut value = fixture();
            value["payload"] = Value::String(bad.into());
            assert!(matches!(parse(&value), Err(EnvelopeError::Base64)), "{bad}");
        }
        for size in [0, 63, 65] {
            let mut value = fixture();
            value["signatures"][0]["sig"] = Value::String(STANDARD.encode(vec![0; size]));
            assert!(matches!(parse(&value), Err(EnvelopeError::SignatureLength)));
        }
        for count in [0, 9] {
            let mut value = fixture();
            value["signatures"] = Value::Array(vec![fixture()["signatures"][0].clone(); count]);
            assert!(matches!(parse(&value), Err(EnvelopeError::SignatureCount)));
        }
        // Repeated signature-shaped entries never create a verified quorum.
        let mut value = fixture();
        value["signatures"] = Value::Array(vec![fixture()["signatures"][0].clone(); 8]);
        assert_eq!(parse(&value).unwrap().signatures().len(), 8);
    }
    #[test]
    fn pae_rejects_oversized_type_and_body() {
        assert!(matches!(
            pre_authentication_encoding(&"a".repeat(257), b""),
            Err(EnvelopeError::PaeLimit)
        ));
        assert!(matches!(
            pre_authentication_encoding("x", &vec![0; crate::json::MAX_INPUT_BYTES + 1]),
            Err(EnvelopeError::PaeLimit)
        ));
    }
}
