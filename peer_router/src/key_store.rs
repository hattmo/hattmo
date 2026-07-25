use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};

const SIGNATURE_SIZE: usize = 64;
const SIGNING_KEY_SIZE: usize = 64;
const VERIFY_KEY_SIZE: usize = 32;
const SIGNED_DATA_HEADER_SIZE: usize = 2 * SIGNATURE_SIZE + VERIFY_KEY_SIZE;
const VERIFY_KEY_OFFSET: usize = SIGNATURE_SIZE;
const DATA_SIG_OFFSET: usize = SIGNATURE_SIZE + VERIFY_KEY_SIZE;

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

    pub fn sign<'a>(&self, data: &[u8], out: &'a mut [u8; SIGNED_DATA_HEADER_SIZE]) {
        let key_sig = self.sig.to_bytes();
        let verify_key = self.key_pair.verifying_key().to_bytes();
        let data_sig = self.key_pair.sign(data).to_bytes();
        out[..VERIFY_KEY_OFFSET].copy_from_slice(&key_sig);
        out[VERIFY_KEY_OFFSET..DATA_SIG_OFFSET].copy_from_slice(&verify_key);
        out[DATA_SIG_OFFSET..].copy_from_slice(&data_sig);
    }

    pub fn verify<'a>(data: &'a [u8], ca: &VerifyingKey) -> Result<&'a [u8], KeyStoreError> {
        let (key_sig, data) = data.split_at_checked(SIGNATURE_SIZE).ok_or(KeyStoreError::MalformedDataHeader)?;
        let (verifying_key, data) = data.split_at_checked(VERIFY_KEY_SIZE).ok_or(KeyStoreError::MalformedDataHeader)?;
        let (data_sig, data) = data.split_at_checked(SIGNATURE_SIZE).ok_or(KeyStoreError::MalformedDataHeader)?;

        let key_sig = Signature::try_from(key_sig).or(Err(KeyStoreError::MalformedDataHeader))?;
        ca.verify(verifying_key, &key_sig).or(Err(KeyStoreError::VerifyError))?;

        let verifying_key = VerifyingKey::try_from(verifying_key).or(Err(KeyStoreError::MalformedDataHeader))?;
        let data_sig = Signature::try_from(data_sig).or(Err(KeyStoreError::MalformedDataHeader))?;
        verifying_key.verify(data, &data_sig).or(Err(KeyStoreError::VerifyError))?;
        Ok(data)
    }
}
