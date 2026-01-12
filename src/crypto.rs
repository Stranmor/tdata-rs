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

    /// Get raw bytes
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
    let encrypted_key = &encrypted[0..16];
    let encrypted_data = &encrypted[16..];

    tracing::debug!(
        "decrypt_local: encrypted len={}, msg_key={:02x?}",
        encrypted.len(),
        encrypted_key
    );

    // Prepare AES key and IV using msg_key
    let (aes_key, aes_iv) = prepare_aes_oldmtp(key.as_bytes(), encrypted_key);

    // Decrypt using AES-256-IGE
    let decrypted = ige_decrypt(&aes_key, &aes_iv, encrypted_data);

    // Verify: SHA1(decrypted)[0..16] must equal encrypted_key
    let check_hash = &sha1_hash(&decrypted)[0..16];

    tracing::debug!(
        "SHA1 check: expected={:02x?}, computed={:02x?}",
        encrypted_key,
        check_hash
    );

    if check_hash != encrypted_key {
        return Err(Error::ChecksumMismatch);
    }

    // First 4 bytes is the original length (little endian)
    if decrypted.len() < 4 {
        return Err(Error::DecryptionFailed);
    }

    let original_len =
        u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;

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
    Ok(decrypted[4..original_len].to_vec())
}

/// Prepare AES key and IV from auth key and message key (old MTProto 1.0 style)
///
/// This matches tdesktop's prepareAES_oldmtp with send=false (for decrypt)
/// For decrypt: x = 8
fn prepare_aes_oldmtp(auth_key: &[u8], msg_key: &[u8]) -> ([u8; AES_KEY_SIZE], [u8; AES_KEY_SIZE]) {
    // For decrypt, x = 8 (send=false in tdesktop)
    let x: usize = 8;

    // sha1_a = SHA1(msgKey + key[x..x+32])
    let sha1_a = sha1_hash_2(msg_key, &auth_key[x..x + 32]);

    // sha1_b = SHA1(key[32+x..48+x] + msgKey + key[48+x..64+x])
    let sha1_b = sha1_hash_3(
        &auth_key[32 + x..48 + x],
        msg_key,
        &auth_key[48 + x..64 + x],
    );

    // sha1_c = SHA1(key[64+x..96+x] + msgKey)
    let sha1_c = sha1_hash_2(&auth_key[64 + x..96 + x], msg_key);

    // sha1_d = SHA1(msgKey + key[96+x..128+x])
    let sha1_d = sha1_hash_2(msg_key, &auth_key[96 + x..128 + x]);

    let mut key = [0u8; AES_KEY_SIZE];
    let mut iv = [0u8; AES_KEY_SIZE];

    // aes_key = sha1_a[0..8] + sha1_b[8..20] + sha1_c[4..16]
    key[0..8].copy_from_slice(&sha1_a[0..8]);
    key[8..20].copy_from_slice(&sha1_b[8..20]);
    key[20..32].copy_from_slice(&sha1_c[4..16]);

    // aes_iv = sha1_a[8..20] + sha1_b[0..8] + sha1_c[16..20] + sha1_d[0..8]
    iv[0..12].copy_from_slice(&sha1_a[8..20]);
    iv[12..20].copy_from_slice(&sha1_b[0..8]);
    iv[20..24].copy_from_slice(&sha1_c[16..20]);
    iv[24..32].copy_from_slice(&sha1_d[0..8]);

    (key, iv)
}

/// AES-256-IGE decryption
fn ige_decrypt(key: &[u8; 32], iv: &[u8; 32], data: &[u8]) -> Vec<u8> {
    use grammers_crypto::aes::ige_decrypt as grammers_ige_decrypt;

    grammers_ige_decrypt(data, key, iv)
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

    #[test]
    fn test_create_local_key_no_passcode() {
        let salt = [0u8; LOCAL_ENCRYPT_SALT_SIZE];
        let passcode = b"";

        let key = create_local_key(&salt, passcode);
        assert_eq!(key.as_bytes().len(), AUTH_KEY_SIZE);
    }

    #[test]
    fn test_create_local_key_with_passcode() {
        let salt = [0u8; LOCAL_ENCRYPT_SALT_SIZE];
        let passcode = b"test";

        let key = create_local_key(&salt, passcode);
        assert_eq!(key.as_bytes().len(), AUTH_KEY_SIZE);

        // Same inputs should produce same key
        let key2 = create_local_key(&salt, passcode);
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_auth_key_from_bytes() {
        let bytes = [0xAB; AUTH_KEY_SIZE];
        let key = AuthKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
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
