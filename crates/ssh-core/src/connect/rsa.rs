//! RSA credential import and signing through AWS-LC.

use ::rsa::pkcs1::EncodeRsaPrivateKey;
use aws_lc_rs::{rand::SystemRandom, signature};
use russh::Signer;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_key::{
    Algorithm, HashAlg, PublicKey, Signature, encoding::Encode, private::RsaKeypair,
};

pub(super) struct RsaSigner {
    key: signature::RsaKeyPair,
    public: PublicKey,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use ::rsa::signature::Verifier;
    use russh::keys::ssh_key::{PrivateKey, encoding::Decode};
    use std::sync::LazyLock;

    static KEY: LazyLock<PrivateKey> =
        LazyLock::new(|| PrivateKey::from(RsaKeypair::random(&mut rand::rng(), 2048).unwrap()));

    #[tokio::test]
    async fn signatures_are_ssh_framed_and_verify_with_both_sha2_algorithms() {
        let mut signer =
            RsaSigner::new(KEY.key_data().rsa().unwrap(), KEY.public_key().clone()).unwrap();
        let identity = AgentIdentity::from(KEY.public_key().clone());
        let message = b"SSH authentication transcript";
        for hash in [HashAlg::Sha256, HashAlg::Sha512] {
            let signed = signer
                .auth_sign(&identity, Some(hash), message.to_vec())
                .await
                .unwrap();
            let (prefix, mut rest) = signed.split_at(message.len());
            assert_eq!(prefix, message);
            let encoded = Vec::<u8>::decode(&mut rest).unwrap();
            assert!(rest.is_empty());
            let mut encoded = encoded.as_slice();
            let signature = Signature::decode(&mut encoded).unwrap();
            assert!(encoded.is_empty());
            assert_eq!(signature.algorithm(), Algorithm::Rsa { hash: Some(hash) });
            Verifier::verify(KEY.public_key(), message, &signature).unwrap();
            assert!(
                Verifier::verify(KEY.public_key(), b"different transcript", &signature).is_err()
            );
        }
    }

    #[tokio::test]
    async fn refuses_sha1_and_a_different_identity() {
        let mut signer =
            RsaSigner::new(KEY.key_data().rsa().unwrap(), KEY.public_key().clone()).unwrap();
        let identity = AgentIdentity::from(KEY.public_key().clone());
        assert!(matches!(
            signer.auth_sign(&identity, None, Vec::new()).await,
            Err(SignError::UnsupportedHash)
        ));
        let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        assert!(matches!(
            signer
                .auth_sign(
                    &AgentIdentity::from(other.public_key().clone()),
                    Some(HashAlg::Sha512),
                    Vec::new()
                )
                .await,
            Err(SignError::UnexpectedIdentity)
        ));
    }
}

impl RsaSigner {
    pub(super) fn new(key: &RsaKeypair, public: PublicKey) -> Result<Self, SignError> {
        // RustCrypto is used only to convert the operator's key format, before
        // connecting. Private signing operations are performed by AWS-LC.
        let imported = ::rsa::RsaPrivateKey::try_from(key).map_err(|_| SignError::InvalidKey)?;
        let der = imported.to_pkcs1_der().map_err(|_| SignError::InvalidKey)?;
        let key =
            signature::RsaKeyPair::from_der(der.as_bytes()).map_err(|_| SignError::InvalidKey)?;
        Ok(Self { key, public })
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SignError {
    #[error("RSA credential cannot be imported")]
    InvalidKey,
    #[error("RSA signing requires SHA-256 or SHA-512")]
    UnsupportedHash,
    #[error("unexpected signing identity")]
    UnexpectedIdentity,
    #[error("RSA signing failed")]
    SigningFailed,
    #[error("SSH authentication transport closed")]
    Send(#[from] russh::SendError),
}

impl Signer for RsaSigner {
    type Error = SignError;

    async fn auth_sign(
        &mut self,
        identity: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        mut to_sign: Vec<u8>,
    ) -> Result<Vec<u8>, Self::Error> {
        match identity {
            AgentIdentity::PublicKey { key, .. } if key.key_data() == self.public.key_data() => {}
            _ => return Err(SignError::UnexpectedIdentity),
        }
        let encoding = match hash_alg {
            Some(HashAlg::Sha256) => &signature::RSA_PKCS1_SHA256,
            Some(HashAlg::Sha512) => &signature::RSA_PKCS1_SHA512,
            _ => return Err(SignError::UnsupportedHash),
        };
        let mut bytes = vec![0; self.key.public_modulus_len()];
        self.key
            .sign(encoding, &SystemRandom::new(), &to_sign, &mut bytes)
            .map_err(|_| SignError::SigningFailed)?;
        let signature = Signature::new(Algorithm::Rsa { hash: hash_alg }, bytes)
            .map_err(|_| SignError::SigningFailed)?;
        let mut encoded = Vec::new();
        signature
            .encode(&mut encoded)
            .map_err(|_| SignError::SigningFailed)?;
        encoded
            .encode(&mut to_sign)
            .map_err(|_| SignError::SigningFailed)?;
        Ok(to_sign)
    }
}
