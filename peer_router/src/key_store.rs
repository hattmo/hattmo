use ed25519_dalek::{Signature, SignatureError, SigningKey, Verifier, VerifyingKey};




pub(crate) struct KeyStore {
    pub(crate) key_pair: SigningKey,
    pub(crate) ca: VerifyingKey,
    pub(crate) sig: Signature,
}

impl KeyStore {
    pub(crate) fn new(key_pair: &[u8; 64], sig: &[u8; 64], ca: &[u8; 32]) -> Result<Self, SignatureError> {
        let key_pair = SigningKey::from_keypair_bytes(key_pair)?;
        let cert = key_pair.verifying_key();
        let ca = VerifyingKey::from_bytes(ca)?;
        let sig = Signature::from_bytes(sig);
        ca.verify(cert.as_bytes(), &sig)?;

        Ok(Self { key_pair, ca, sig })
    }
}

