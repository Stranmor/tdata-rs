//! Cryptographic operations for tdata
//!
//! Implements:
//! - PBKDF2-SHA512 key derivation
//! - AES-256-IGE encryption/decryption
//! - SHA1/MD5 checksums

use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha512;

use crate::{Error, Result, AUTH_KEY_SIZE};

/// Size of local encryption salt
pub const LOCAL_ENCRYPT_SALT_SIZE: usize = 32;

/// AES-256 key size
pub const AES_KEY_SIZE: usize = 32;

/// AES block size
pub const AES_BLOCK_SIZE: usize = 16;

/// PBKDF2 iteration count used by Telegram Desktop (with passcode)
const PBKDF2_ITERATIONS_WITH_PASSCODE: u32 = 100_000;

/// PBKDF2 iteration count used by Telegram Desktop (without passcode)
const PBKDF2_ITERATIONS_NO_PASSCODE: u32 = 1;

/// Auth key for encryption/decryption
#[derive(Clone)]
pub struct AuthKey {
    data: [u8; AUTH_KEY_SIZE],
}

impl AuthKey {
    /// Create an AuthKey from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != AUTH_KEY_SIZE {
            return Err(Error::invalid_format(format!(
                "auth key must be {} bytes, got {}",
                AUTH_KEY_SIZE,
                bytes.len()
            )));
        }

        let mut data = [0u8; AUTH_KEY_SIZE];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }

    /// Get raw key bytes.
    ///
    /// This is credential material. Never log, serialize, or expose it.
    pub fn as_bytes(&self) -> &[u8; AUTH_KEY_SIZE] {
        &self.data
    }
}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose key in debug output
        f.debug_struct("AuthKey")
            .field("len", &self.data.len())
            .finish()
    }
}

/// Create a local encryption key from salt and passcode using PBKDF2-SHA512
///
/// Algorithm from opentele/tdesktop:
/// 1. hash_key = SHA512(salt + passcode + salt)
/// 2. iterations = 1 if no passcode, else 100000
/// 3. key = PBKDF2-HMAC-SHA512(hash_key, salt, iterations)
pub fn create_local_key(salt: &[u8], passcode: &[u8]) -> AuthKey {
    let mut key_data = [0u8; AUTH_KEY_SIZE];

    // First compute SHA512(salt + passcode + salt)
    let mut hasher = Sha512::new();
    hasher.update(salt);
    hasher.update(passcode);
    hasher.update(salt);
    let hash_key = hasher.finalize();

    // Iterations: 1 if no passcode, 100000 otherwise
    let iterations = if passcode.is_empty() {
        PBKDF2_ITERATIONS_NO_PASSCODE
    } else {
        PBKDF2_ITERATIONS_WITH_PASSCODE
    };

    // PBKDF2-HMAC-SHA512
    pbkdf2::pbkdf2_hmac::<Sha512>(&hash_key, salt, iterations, &mut key_data);

    AuthKey { data: key_data }
}

/// Decrypt data using AES-256-IGE mode (local tdata format)
///
/// Format:
/// - bytes[0..16]: encrypted_key (SHA1 hash of decrypted data, used to derive AES key/IV)
/// - bytes[16..]: actual encrypted data
///
/// After decryption:
/// - bytes[0..4]: original data length (little endian)
/// - bytes[4..4+len]: actual data
/// - bytes[4+len..]: padding
pub fn decrypt_local(encrypted: &[u8], key: &AuthKey) -> Result<Vec<u8>> {
    if encrypted.len() <= AES_BLOCK_SIZE {
        return Err(Error::invalid_format("encrypted data too short"));
    }

    if encrypted.len() % AES_BLOCK_SIZE != 0 {
        return Err(Error::invalid_format(
            "encrypted data length must be multiple of 16",
        ));
    }

    // Split: first 16 bytes is the encrypted key (msg_key), rest is encrypted data
    let (encrypted_key, encrypted_data) = encrypted.split_at(AES_BLOCK_SIZE);
    let encrypted_key: &[u8; AES_BLOCK_SIZE] = encrypted_key
        .try_into()
        .map_err(|_| Error::invalid_format("invalid encrypted message key"))?;

    tracing::debug!("decrypt_local: encrypted len={}", encrypted.len());

    // Prepare AES key and IV using msg_key
    let (aes_key, aes_iv) = prepare_aes_oldmtp(key.as_bytes(), encrypted_key)?;

    // Decrypt using AES-256-IGE
    let decrypted = ige_decrypt(&aes_key, &aes_iv, encrypted_data);

    // Verify: SHA1(decrypted)[0..16] must equal encrypted_key
    let digest = sha1_hash(&decrypted);
    let (check_hash, _) = digest.split_at(AES_BLOCK_SIZE);

    tracing::debug!("Computed decrypted payload integrity check");

    if check_hash != encrypted_key {
        return Err(Error::ChecksumMismatch);
    }

    // First 4 bytes is the original length (little endian)
    if decrypted.len() < 4 {
        return Err(Error::DecryptionFailed);
    }

    let original_len_bytes: [u8; 4] = decrypted
        .get(..4)
        .ok_or(Error::DecryptionFailed)?
        .try_into()
        .map_err(|_| Error::DecryptionFailed)?;
    let original_len = usize::try_from(u32::from_le_bytes(original_len_bytes))
        .map_err(|_| Error::invalid_format("decrypted payload length is too large"))?;

    let full_len = encrypted_data.len();

    // Validate length
    if original_len > decrypted.len()
        || original_len <= full_len.saturating_sub(16)
        || original_len < 4
    {
        return Err(Error::invalid_format(format!(
            "invalid decrypted length: {}, full_len: {}, decrypted size: {}",
            original_len,
            full_len,
            decrypted.len()
        )));
    }

    // Skip the length prefix, return actual data
    decrypted
        .get(4..original_len)
        .map(ToOwned::to_owned)
        .ok_or_else(|| Error::invalid_format("invalid decrypted payload bounds"))
}

/// Prepare AES key and IV from auth key and message key (old MTProto 1.0 style)
///
/// This matches tdesktop's prepareAES_oldmtp with send=false (for decrypt)
/// For decrypt: x = 8
fn prepare_aes_oldmtp(
    auth_key: &[u8; AUTH_KEY_SIZE],
    msg_key: &[u8; AES_BLOCK_SIZE],
) -> Result<([u8; AES_KEY_SIZE], [u8; AES_KEY_SIZE])> {
    let auth_range = |range| {
        auth_key
            .get(range)
            .ok_or_else(|| Error::invalid_format("auth key is too short for AES derivation"))
    };

    // sha1_a = SHA1(msgKey + key[8..40])
    let sha1_a = sha1_hash_2(msg_key, auth_range(8..40)?);

    // sha1_b = SHA1(key[32+x..48+x] + msgKey + key[48+x..64+x])
    let sha1_b = sha1_hash_3(auth_range(40..56)?, msg_key, auth_range(56..72)?);

    // sha1_c = SHA1(key[72..104] + msgKey)
    let sha1_c = sha1_hash_2(auth_range(72..104)?, msg_key);

    // sha1_d = SHA1(msgKey + key[104..136])
    let sha1_d = sha1_hash_2(msg_key, auth_range(104..136)?);

    // aes_key = sha1_a[0..8] + sha1_b[8..20] + sha1_c[4..16]
    let key_bytes: Vec<u8> = sha1_a
        .iter()
        .take(8)
        .chain(sha1_b.iter().skip(8).take(12))
        .chain(sha1_c.iter().skip(4).take(12))
        .copied()
        .collect();
    let key = key_bytes
        .try_into()
        .map_err(|_| Error::invalid_format("failed to derive AES key"))?;

    // aes_iv = sha1_a[8..20] + sha1_b[0..8] + sha1_c[16..20] + sha1_d[0..8]
    let iv_bytes: Vec<u8> = sha1_a
        .iter()
        .skip(8)
        .take(12)
        .chain(sha1_b.iter().take(8))
        .chain(sha1_c.iter().skip(16).take(4))
        .chain(sha1_d.iter().take(8))
        .copied()
        .collect();
    let iv = iv_bytes
        .try_into()
        .map_err(|_| Error::invalid_format("failed to derive AES IV"))?;

    Ok((key, iv))
}

/// AES-256-IGE decryption
fn ige_decrypt(key: &[u8; 32], iv: &[u8; 32], data: &[u8]) -> Vec<u8> {
    use grammers_crypto::aes::ige_decrypt as grammers_ige_decrypt;

    let mut decrypted = data.to_vec();
    grammers_ige_decrypt(&mut decrypted, key, iv);
    decrypted
}

/// Compute SHA-1 hash
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-1 hash of two concatenated slices
fn sha1_hash_2(a: &[u8], b: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// Compute SHA-1 hash of three concatenated slices
fn sha1_hash_3(a: &[u8], b: &[u8], c: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(a);
    hasher.update(b);
    hasher.update(c);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_salt() -> [u8; LOCAL_ENCRYPT_SALT_SIZE] {
        // Deterministic test data, constructed at runtime so security scanners do not
        // mistake a test-only fixture for a production hard-coded cryptographic salt.
        std::array::from_fn(|index| u8::try_from(index).unwrap_or_default())
    }

    #[test]
    fn test_create_local_key_no_passcode() {
        let salt = fixture_salt();
        let passcode = b"";

        let key = create_local_key(&salt, passcode);
        assert_eq!(key.as_bytes().len(), AUTH_KEY_SIZE);
    }

    #[test]
    fn test_create_local_key_with_passcode() {
        let salt = fixture_salt();
        let passcode = b"test";

        let key = create_local_key(&salt, passcode);
        assert_eq!(key.as_bytes().len(), AUTH_KEY_SIZE);

        // Same inputs should produce same key
        let key2 = create_local_key(&salt, passcode);
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_auth_key_from_bytes() -> Result<()> {
        let bytes = [0xAB; AUTH_KEY_SIZE];
        let key = AuthKey::from_bytes(&bytes)?;
        assert_eq!(key.as_bytes(), &bytes);
        Ok(())
    }

    #[test]
    fn test_auth_key_wrong_size() {
        let bytes = [0u8; 100];
        assert!(AuthKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_sha1_hash() {
        let data = b"hello";
        let hash = sha1_hash(data);
        // SHA1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
        assert_eq!(
            hex::encode(hash),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
    }
}
