//! Cryptographic matching only. Caller-supplied keys do not confer authority.
use crate::envelope::HeaderEnvelopeCandidate;
use ed25519_dalek::{Signature, VerifyingKey};
use std::fmt;

pub const MAX_SIGNED_BYTES: usize = crate::json::MAX_INPUT_BYTES + 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    InvalidKey,
    WeakKey,
    InvalidSignature,
    MessageTooLarge,
    SignatureIndex,
    SigningBytes,
}
impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "公钥编码无效",
            Self::WeakKey => "拒绝低阶弱公钥",
            Self::InvalidSignature => "签名不匹配",
            Self::MessageTooLarge => "待验签数据超过限制",
            Self::SignatureIndex => "签名候选索引不存在",
            Self::SigningBytes => "无法构造待签字节",
        })
    }
}
impl std::error::Error for SignatureError {}

/// Pure Ed25519 over exact bytes, not Ed25519ph/ctx. No identity or policy lookup.
pub fn verify_ed25519(
    message: &[u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), SignatureError> {
    if message.len() > MAX_SIGNED_BYTES {
        return Err(SignatureError::MessageTooLarge);
    }
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| SignatureError::InvalidKey)?;
    if key.is_weak() {
        return Err(SignatureError::WeakKey);
    }
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| SignatureError::InvalidSignature)
}

/// Binds one successful cryptographic check to the exact immutable envelope.
/// This result deliberately has no authorized/trusted/source-verified flag.
#[derive(Debug)]
pub struct CryptographicMatch<'a> {
    envelope: &'a HeaderEnvelopeCandidate,
    public_key: [u8; 32],
    signature_index: usize,
}
impl<'a> CryptographicMatch<'a> {
    pub fn envelope(&self) -> &'a HeaderEnvelopeCandidate {
        self.envelope
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn signature_index(&self) -> usize {
        self.signature_index
    }
}

impl HeaderEnvelopeCandidate {
    /// The external key is used directly; unauthenticated keyid is never consulted.
    pub fn match_signature(
        &self,
        signature_index: usize,
        external_public_key: &[u8; 32],
    ) -> Result<CryptographicMatch<'_>, SignatureError> {
        let signature = self
            .signatures()
            .get(signature_index)
            .ok_or(SignatureError::SignatureIndex)?;
        let bytes = self
            .signing_bytes()
            .map_err(|_| SignatureError::SigningBytes)?;
        verify_ed25519(&bytes, external_public_key, signature.bytes())?;
        Ok(CryptographicMatch {
            envelope: self,
            public_key: *external_public_key,
            signature_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    // RFC 8032 section 7.1 public test material, never a deployed key.
    const PK1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG1: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    fn hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        std::array::from_fn(|i| u8::from_str_radix(&input[i * 2..i * 2 + 2], 16).unwrap())
    }
    #[test]
    fn rfc8032_vectors_empty_one_and_two_byte_messages() {
        for (key, message, signature) in [
            (PK1, vec![], SIG1),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                vec![0x72],
                concat!(
                    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
                ),
            ),
            (
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                vec![0xaf, 0x82],
                concat!(
                    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
                    "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
                ),
            ),
        ] {
            assert_eq!(verify_ed25519(&message, &hex(key), &hex(signature)), Ok(()));
        }
    }
    #[test]
    fn rejects_every_single_byte_signature_mutation_and_changed_message() {
        let original: [u8; 64] = hex(SIG1);
        for index in 0..64 {
            let mut signature = original;
            signature[index] ^= 1;
            assert!(verify_ed25519(b"", &hex(PK1), &signature).is_err());
        }
        assert!(verify_ed25519(b"x", &hex(PK1), &original).is_err());
        let other = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        assert!(verify_ed25519(b"", &other, &original).is_err());
    }
    #[test]
    fn rejects_weak_keys_low_order_r_and_noncanonical_scalar() {
        let mut identity = [0; 32];
        identity[0] = 1;
        assert_eq!(
            verify_ed25519(b"", &identity, &hex(SIG1)),
            Err(SignatureError::WeakKey)
        );
        let mut signature: [u8; 64] = hex(SIG1);
        signature[..32].copy_from_slice(&identity);
        assert_eq!(
            verify_ed25519(b"", &hex(PK1), &signature),
            Err(SignatureError::InvalidSignature)
        );
        let mut signature: [u8; 64] = hex(SIG1);
        signature[32..].fill(255);
        assert_eq!(
            verify_ed25519(b"", &hex(PK1), &signature),
            Err(SignatureError::InvalidSignature)
        );
    }
    fn signed_fixture() -> (serde_json::Value, [u8; 32]) {
        let header = serde_json::json!({
            "schema":crate::header::SCHEMA,"project":"p1",
            "position":{"source":"ci1","epoch":"e1","sequence":"0"},
            "kind":"test.failed","subject":format!("sha256:{}", "a".repeat(64))
        });
        let payload = crate::json::canonicalize(&serde_json::to_vec(&header).unwrap()).unwrap();
        let pae =
            crate::envelope::pre_authentication_encoding(crate::envelope::PAYLOAD_TYPE, &payload)
                .unwrap();
        // Synthetic unit fixture only; independent signing fixture is checked separately.
        let key = SigningKey::from_bytes(&[42; 32]);
        (
            serde_json::json!({
                "payloadType":crate::envelope::PAYLOAD_TYPE, "payload":STANDARD.encode(payload),
                "signatures":[{"keyid":"untrusted-hint","sig":STANDARD.encode(key.sign(&pae).to_bytes())}]
            }),
            key.verifying_key().to_bytes(),
        )
    }
    fn parse(value: &serde_json::Value) -> HeaderEnvelopeCandidate {
        HeaderEnvelopeCandidate::parse(&serde_json::to_vec(value).unwrap()).unwrap()
    }
    #[test]
    fn successful_match_binds_key_index_and_exact_candidate() {
        let (value, key) = signed_fixture();
        let candidate = parse(&value);
        let result = candidate.match_signature(0, &key).unwrap();
        assert!(std::ptr::eq(result.envelope(), &candidate));
        assert_eq!(result.public_key(), &key);
        assert_eq!(result.signature_index(), 0);
        assert!(matches!(
            candidate.match_signature(1, &key),
            Err(SignatureError::SignatureIndex)
        ));
    }
    #[test]
    fn key_hint_changes_never_change_cryptographic_result() {
        let (mut value, key) = signed_fixture();
        value["signatures"][0]["keyid"] = serde_json::Value::String("another-key".into());
        assert!(parse(&value).match_signature(0, &key).is_ok());
        value["signatures"][0]
            .as_object_mut()
            .unwrap()
            .remove("keyid");
        assert!(parse(&value).match_signature(0, &key).is_ok());
    }
    #[test]
    fn payload_change_and_raw_payload_signature_fail() {
        let (mut value, key) = signed_fixture();
        let raw = STANDARD.decode(value["payload"].as_str().unwrap()).unwrap();
        let changed = String::from_utf8(raw.clone())
            .unwrap()
            .replace("test.failed", "test.passed");
        value["payload"] = serde_json::Value::String(STANDARD.encode(changed));
        assert!(parse(&value).match_signature(0, &key).is_err());
        value["payload"] = serde_json::Value::String(STANDARD.encode(&raw));
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        value["signatures"][0]["sig"] =
            serde_json::Value::String(STANDARD.encode(signing_key.sign(&raw).to_bytes()));
        assert!(parse(&value).match_signature(0, &key).is_err());
    }
    #[test]
    fn rejects_oversized_message_before_crypto_work() {
        assert_eq!(
            verify_ed25519(&vec![0; MAX_SIGNED_BYTES + 1], &hex(PK1), &hex(SIG1)),
            Err(SignatureError::MessageTooLarge)
        );
    }
}

#[cfg(test)]
mod independent_fixture_test {
    #[test]
    fn python_generated_dsse_signature_matches_exact_candidate() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../ed25519_fixture.json")).unwrap();
        let hex = fixture["public_key_hex"].as_str().unwrap();
        let key: [u8; 32] =
            std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
        let candidate = crate::envelope::HeaderEnvelopeCandidate::parse(
            &serde_json::to_vec(&fixture["envelope"]).unwrap(),
        )
        .unwrap();
        assert!(candidate.match_signature(0, &key).is_ok());
    }
}
