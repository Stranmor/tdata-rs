//! Account representation

use crate::{Result, AUTH_KEY_SIZE};

/// Telegram datacenter addresses (production)
const DC_ADDRESSES: [(i32, &str, u16); 5] = [
    (1, "149.154.175.53", 443),
    (2, "149.154.167.51", 443),
    (3, "149.154.175.100", 443),
    (4, "149.154.167.91", 443),
    (5, "91.108.56.130", 443),
];

/// A Telegram account extracted from tdata
#[derive(Debug)]
pub struct Account {
    /// Account index (0-2)
    index: i32,
    /// Datacenter ID (1-5)
    dc_id: i32,
    /// User ID
    user_id: i64,
    /// Authorization key (256 bytes)
    auth_key: [u8; AUTH_KEY_SIZE],
}

impl Account {
    /// Create a new account
    pub(crate) fn new(index: i32, dc_id: i32, user_id: i64, auth_key: [u8; AUTH_KEY_SIZE]) -> Self {
        Self {
            index,
            dc_id,
            user_id,
            auth_key,
        }
    }

    /// Get the account index (0-2)
    pub fn index(&self) -> i32 {
        self.index
    }

    /// Get the datacenter ID (1-5)
    pub fn dc_id(&self) -> i32 {
        self.dc_id
    }

    /// Get the user ID
    pub fn user_id(&self) -> i64 {
        self.user_id
    }

    /// Get the raw auth key bytes
    pub fn auth_key_bytes(&self) -> &[u8; AUTH_KEY_SIZE] {
        &self.auth_key
    }

    /// Convert to grammers SessionData
    ///
    /// Returns the session data that can be imported to any grammers Session
    pub fn to_grammers_session_data(&self) -> grammers_session::SessionData {
        use grammers_session::{defs::DcOption, SessionData};
        use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

        // Get or create DC option with auth key
        let (ip, port) = DC_ADDRESSES
            .iter()
            .find(|(id, _, _)| *id == self.dc_id)
            .map(|(_, ip, port)| (*ip, *port))
            .unwrap_or(("149.154.167.51", 443));

        let ipv4: Ipv4Addr = ip.parse().unwrap();
        let ipv6 = ipv4.to_ipv6_mapped();

        let mut session_data = SessionData {
            home_dc: self.dc_id,
            ..SessionData::default()
        };

        // Update the DC option with our auth key
        if let Some(dc_option) = session_data.dc_options.get_mut(&self.dc_id) {
            dc_option.auth_key = Some(self.auth_key);
        } else {
            session_data.dc_options.insert(
                self.dc_id,
                DcOption {
                    id: self.dc_id,
                    ipv4: SocketAddrV4::new(ipv4, port),
                    ipv6: SocketAddrV6::new(ipv6, port, 0, 0),
                    auth_key: Some(self.auth_key),
                },
            );
        }

        session_data
    }

    /// Export session as a base64 string (portable format)
    ///
    /// This string can be used to initialize a grammers client
    pub fn to_session_string(&self) -> Result<String> {
        // For portable session strings, we use a simple custom format:
        // version(1) | dc_id(1) | user_id(8) | auth_key(256)
        let mut data = Vec::with_capacity(1 + 1 + 8 + 256);

        // Version 1
        data.push(1u8);
        // DC ID
        data.push(self.dc_id as u8);
        // User ID (little endian)
        data.extend_from_slice(&self.user_id.to_le_bytes());
        // Auth key
        data.extend_from_slice(&self.auth_key);

        Ok(base64_encode(&data))
    }
}

/// Base64 encode without external dependency
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as usize;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as usize
        } else {
            0
        };

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_creation() {
        let auth_key = [0xAB; AUTH_KEY_SIZE];
        let account = Account::new(0, 2, 12345678, auth_key);

        assert_eq!(account.index(), 0);
        assert_eq!(account.dc_id(), 2);
        assert_eq!(account.user_id(), 12345678);
        assert_eq!(account.auth_key_bytes(), &auth_key);
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
