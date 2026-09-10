use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};

pub(crate) const SIGNATURE_SIZE: usize = 64;
pub(crate) const SIGNING_KEY_SIZE: usize = 64;
pub(crate) const VERIFY_KEY_SIZE: usize = 32;
pub(crate) const SIGNED_DATA_HEADER_SIZE: usize = 2 * SIGNATURE_SIZE + VERIFY_KEY_SIZE;
pub(crate) const VERIFY_KEY_OFFSET: usize = SIGNATURE_SIZE;
pub(crate) const DATA_SIG_OFFSET: usize = SIGNATURE_SIZE + VERIFY_KEY_SIZE;

pub struct KeyStore {
    pub key_pair: SigningKey,
    pub ca: VerifyingKey,
    pub sig: Signature,
}

pub enum KeyStoreError {
    MalformedDataHeader,
    SignatureError(SignatureError),
    VerifyError,
}

impl From<SignatureError> for KeyStoreError {
    fn from(value: SignatureError) -> Self {
        Self::SignatureError(value)
    }
}

impl KeyStore {
    pub fn new(key_pair: &[u8; SIGNING_KEY_SIZE], sig: &[u8; SIGNATURE_SIZE], ca: &[u8; VERIFY_KEY_SIZE]) -> Result<Self, KeyStoreError> {
        let key_pair = SigningKey::from_keypair_bytes(key_pair)?;
        let cert = key_pair.verifying_key();
        let ca = VerifyingKey::from_bytes(ca)?;
        let sig = Signature::from_bytes(sig);
        ca.verify(cert.as_bytes(), &sig)?;

        Ok(Self { key_pair, ca, sig })
    }

    pub fn sign<'a,'b>(&self, data: &'a [u8], sig: &'b mut [u8; SIGNED_DATA_HEADER_SIZE]) {
        let key_sig = self.sig.to_bytes();
        let verify_key = self.key_pair.verifying_key().to_bytes();
        let data_sig = self.key_pair.sign(data).to_bytes();
        sig[..VERIFY_KEY_OFFSET].copy_from_slice(&key_sig);
        sig[VERIFY_KEY_OFFSET..DATA_SIG_OFFSET].copy_from_slice(&verify_key);
        sig[DATA_SIG_OFFSET..].copy_from_slice(&data_sig);
    }

    pub fn verify<'a, 'b>(&self, data: &'a [u8], sig: &'b [u8; SIGNED_DATA_HEADER_SIZE]) -> Result<(), KeyStoreError> {
        let (key_sig, sig) = sig.split_at(SIGNATURE_SIZE);
        let (verifying_key, data_sig) = sig.split_at(VERIFY_KEY_SIZE);

        let key_sig = Signature::try_from(key_sig).or(Err(KeyStoreError::MalformedDataHeader))?;
        self.ca.verify(verifying_key, &key_sig).or(Err(KeyStoreError::VerifyError))?;

        let verifying_key = VerifyingKey::try_from(verifying_key).or(Err(KeyStoreError::MalformedDataHeader))?;
        let data_sig = Signature::try_from(data_sig).or(Err(KeyStoreError::MalformedDataHeader))?;
        verifying_key.verify(data, &data_sig).or(Err(KeyStoreError::VerifyError))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ed25519_dalek::{SigningKey,Signer};

use super::*;
    #[test]
    fn test_sign_and_verify(){
        SigningKey::generate();
        let ks = KeyStore::new(key_pair, sig, ca);
    }
}
