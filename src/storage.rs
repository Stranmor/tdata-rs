//! Storage utilities for reading tdata files
//!
//! Handles reading and parsing of key files, map files, and account data.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{create_local_key, decrypt_local, AuthKey};
use crate::qdatastream::QDataStream;
use crate::{Error, Result, MAX_ACCOUNTS};

/// Magic bytes at the start of tdata files
const TDATA_MAGIC: [u8; 4] = [0x54, 0x44, 0x46, 0x24]; // "TDF$"

/// File descriptor for reading tdata files
#[derive(Debug)]
pub struct FileDescriptor {
    pub version: u32,
    pub data: Vec<u8>,
}

/// Read a tdata file
pub fn read_file(name: &str, base_path: &Path) -> Result<FileDescriptor> {
    let path = base_path.join(name);
    let path_s = base_path.join(format!("{}s", name));

    tracing::debug!("Trying to read file: {:?}", path);

    // Try main file first, then backup (s suffix)
    // Use is_file() to skip directories
    let file_data = if path.is_file() {
        tracing::debug!("Reading main file: {:?}", path);
        fs::read(&path)?
    } else if path_s.is_file() {
        tracing::debug!("Reading backup file: {:?}", path_s);
        fs::read(&path_s)?
    } else {
        return Err(Error::FileNotFound {
            file: name.to_string(),
            folder: base_path.to_path_buf(),
        });
    };

    tracing::debug!("Read {} bytes", file_data.len());
    parse_file_descriptor(&file_data)
}

/// Parse a file descriptor from raw bytes
///
/// File format:
/// - bytes[0..4]: magic "TDF$"
/// - bytes[4..8]: version (little endian)
/// - bytes[8..len-16]: data payload
/// - bytes[len-16..len]: MD5 checksum of (data + dataSize + version + magic)
fn parse_file_descriptor(data: &[u8]) -> Result<FileDescriptor> {
    if data.len() < 8 + 16 {
        return Err(Error::invalid_format("file too short"));
    }

    // Check magic
    if &data[0..4] != TDATA_MAGIC {
        return Err(Error::invalid_format("invalid file magic"));
    }

    // Read version (little endian)
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    // Data is between header and MD5
    let data_size = data.len() - 8 - 16;
    let payload = &data[8..8 + data_size];
    let file_md5 = &data[data.len() - 16..];

    // Verify MD5: data + dataSize(LE) + version(LE) + magic
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(payload);
    hasher.update((data_size as u32).to_le_bytes());
    hasher.update(version.to_le_bytes());
    hasher.update(TDATA_MAGIC);
    let computed_md5: [u8; 16] = hasher.finalize().into();

    tracing::debug!(
        "MD5 check: file={:02x?}, computed={:02x?}",
        file_md5,
        computed_md5
    );

    if file_md5 != computed_md5.as_slice() {
        return Err(Error::ChecksumMismatch);
    }

    Ok(FileDescriptor {
        version,
        data: payload.to_vec(),
    })
}

/// Key data parsed from key_data file
#[derive(Debug)]
pub struct KeyData {
    pub salt: Vec<u8>,
    pub key_encrypted: Vec<u8>,
    pub info_encrypted: Vec<u8>,
    pub version: u32,
}

/// Parse the key_data file
pub fn read_key_data(base_path: &Path, key_file: &str) -> Result<KeyData> {
    let name = format!("key_{}", key_file);
    let file = read_file(&name, base_path)?;

    let mut stream = QDataStream::new(&file.data);

    let salt = stream.read_qbytearray()?;
    let key_encrypted = stream.read_qbytearray()?;
    let info_encrypted = stream.read_qbytearray()?;

    Ok(KeyData {
        salt,
        key_encrypted,
        info_encrypted,
        version: file.version,
    })
}

/// Decrypted key info containing account indices
#[derive(Debug)]
pub struct KeyInfo {
    pub local_key: AuthKey,
    pub account_indices: Vec<i32>,
}

/// Decrypt the key data
pub fn decrypt_key_data(key_data: &KeyData, passcode: &[u8]) -> Result<KeyInfo> {
    // Create passcode key from salt
    let passcode_key = create_local_key(&key_data.salt, passcode);

    // Decrypt the key_encrypted to get the local key
    let decrypted_key = decrypt_local(&key_data.key_encrypted, &passcode_key)?;

    if decrypted_key.len() < 256 {
        return Err(Error::invalid_format(format!(
            "decrypted key too short: {} bytes",
            decrypted_key.len()
        )));
    }

    let local_key = AuthKey::from_bytes(&decrypted_key[..256])?;

    // Decrypt info to get account indices
    let decrypted_info = decrypt_local(&key_data.info_encrypted, &local_key)?;
    let mut info_stream = QDataStream::new(&decrypted_info);

    let count = info_stream.read_i32()?;
    
    if count <= 0 || count > MAX_ACCOUNTS as i32 {
        return Err(Error::invalid_format(format!(
            "invalid account count: {}",
            count
        )));
    }

    let mut account_indices = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let index = info_stream.read_i32()?;
        if index >= 0 && index < MAX_ACCOUNTS as i32 {
            account_indices.push(index);
        }
    }

    Ok(KeyInfo {
        local_key,
        account_indices,
    })
}


/// Read MTP data file (contains the actual auth key)
///
/// The MTP data is stored in a file named by ToFilePart(ComputeDataNameKey(keyFile))
/// where keyFile is like "data" or "data#1" for multi-account
pub fn read_mtp_data(
    base_path: &Path,
    index: i32,
    local_key: &AuthKey,
    key_file: &str,
) -> Result<MtpData> {
    // Compute data name key = MD5(keyFile)
    let data_name = compose_data_string(key_file, index);
    let data_name_key = compute_data_name_key(&data_name);
    let file_name = to_file_part(data_name_key);
    
    tracing::debug!("Looking for MTP data in file: {}", file_name);
    
    // Read the encrypted file
    let file = read_file(&file_name, base_path)?;
    
    // The file contains a QByteArray which is the encrypted data
    let mut stream = QDataStream::new(&file.data);
    let encrypted = stream.read_qbytearray()?;
    
    // Decrypt
    let decrypted = decrypt_local(&encrypted, local_key)?;
    
    // Parse the decrypted MTP data
    parse_mtp_authorization(&decrypted)
}

/// Compose data string: "data" for index 0, "data#2" for index 1, etc.
fn compose_data_string(key_file: &str, index: i32) -> String {
    let base = key_file.replace('#', "");
    if index > 0 {
        format!("{}#{}", base, index + 1)
    } else {
        base
    }
}

/// Compute data name key from key file name using MD5
fn compute_data_name_key(data_name: &str) -> u64 {
    use md5::{Digest, Md5};
    
    let mut hasher = Md5::new();
    hasher.update(data_name.as_bytes());
    let result: [u8; 16] = hasher.finalize().into();
    
    // Take lower 64 bits (little endian)
    u64::from_le_bytes([
        result[0], result[1], result[2], result[3],
        result[4], result[5], result[6], result[7],
    ])
}

/// Convert a FileKey (u64) to a 16-character hex file name
fn to_file_part(val: u64) -> String {
    let mut result = String::with_capacity(16);
    let mut v = val;
    
    for _ in 0..16 {
        let nibble = (v & 0x0F) as u8;
        let c = if nibble < 0x0A {
            (b'0' + nibble) as char
        } else {
            (b'A' + (nibble - 0x0A)) as char
        };
        result.push(c);
        v >>= 4;
    }
    
    result
}

/// MTP authorization data
#[derive(Debug)]
pub struct MtpData {
    pub dc_id: i32,
    pub user_id: i64,
    pub auth_key: [u8; 256],
}

/// Special tag for wide (64-bit) user IDs
const K_WIDE_IDS_TAG: i64 = !0i64; // All bits set = -1

/// Parse MTP authorization data from decrypted bytes
///
/// Format:
/// - int32: block_id (must be 0x4B = dbi.MtpAuthorization)
/// - QByteArray: serialized authorization data
///
/// Serialized format:
/// - int32: userId (or kWideIdsTag for new format)
/// - int32: mainDcId (or if kWideIdsTag: int64 userId, int32 mainDcId)
/// - int32: keysCount
/// - for each key:
///   - int32: dcId
///   - bytes[256]: authKey
/// - int32: keysToDestroyCount
/// - ...
fn parse_mtp_authorization(data: &[u8]) -> Result<MtpData> {
    let mut stream = QDataStream::new(data);
    
    // Read block ID
    let block_id = stream.read_i32()?;
    
    // 0x4B = 75 = dbi.MtpAuthorization
    if block_id != 0x4B {
        return Err(Error::invalid_format(format!(
            "expected MtpAuthorization block (0x4B), got 0x{:02X}",
            block_id
        )));
    }
    
    // Read the serialized QByteArray
    let serialized = stream.read_qbytearray()?;
    let mut auth_stream = QDataStream::new(&serialized);
    
    // Read user ID and DC ID
    let first_int = auth_stream.read_i32()?;
    let second_int = auth_stream.read_i32()?;
    
    // Check for kWideIdsTag (new format with 64-bit user ID)
    let combined = ((first_int as i64) << 32) | (second_int as u32 as i64);
    
    let (user_id, main_dc_id) = if combined == K_WIDE_IDS_TAG {
        // New format: next is int64 userId, then int32 mainDcId
        let uid = auth_stream.read_i64()?;
        let dc = auth_stream.read_i32()?;
        (uid, dc)
    } else {
        // Old format: first_int is userId, second_int is mainDcId
        (first_int as i64, second_int)
    };
    
    tracing::debug!("MTP auth: user_id={}, main_dc_id={}", user_id, main_dc_id);
    
    // Read keys count
    let keys_count = auth_stream.read_i32()?;
    
    if keys_count < 0 || keys_count > 10 {
        return Err(Error::invalid_format(format!(
            "invalid keys count: {}",
            keys_count
        )));
    }
    
    // Read auth keys
    let mut auth_key: Option<[u8; 256]> = None;
    
    for _ in 0..keys_count {
        let dc_id = auth_stream.read_i32()?;
        let key_bytes = auth_stream.read_raw(256)?;
        
        tracing::debug!("Found key for DC {}", dc_id);
        
        if dc_id == main_dc_id {
            let mut key = [0u8; 256];
            key.copy_from_slice(&key_bytes);
            auth_key = Some(key);
        }
    }
    
    let auth_key = auth_key.ok_or_else(|| {
        Error::auth_key_failed(format!("no auth key found for main DC {}", main_dc_id))
    })?;
    
    Ok(MtpData {
        dc_id: main_dc_id,
        user_id,
        auth_key,
    })
}

/// Get the absolute path, expanding ~ if needed
pub fn get_absolute_path(path: &str) -> PathBuf {
    if path.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

/// Get default tdata path for the current OS
pub fn get_default_tdata_path() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        dirs::home_dir().map(|h| h.join(".local/share/TelegramDesktop/tdata"))
    }

    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Application Support/Telegram Desktop/tdata"))
    }

    #[cfg(target_os = "windows")]
    {
        dirs::data_local_dir().map(|d| d.join("Telegram Desktop/tdata"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}
