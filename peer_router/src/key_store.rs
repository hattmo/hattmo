use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};

pub struct KeyStore {
    pub key_pair: SigningKey,
    pub ca: VerifyingKey,
    pub sig: Signature,
}

impl KeyStore {
    pub fn new(key_pair: &[u8; 64], sig: &[u8; 64], ca: &[u8; 32]) -> Result<Self, SignatureError> {
        let key_pair = SigningKey::from_keypair_bytes(key_pair)?;
        let cert = key_pair.verifying_key();
        let ca = VerifyingKey::from_bytes(ca)?;
        let sig = Signature::from_bytes(sig);
        ca.verify(cert.as_bytes(), &sig)?;

        Ok(Self { key_pair, ca, sig })
    }

    pub fn sign(&self, data: &[u8]) {
        let sig = self.key_pair.sign(data).to_bytes();
        let verify_key = self.key_pair.verifying_key().to_bytes();
        let ca_sig = self.sig.to_bytes();
        let mut out = [0;]
        memcpy

    } 
}

