//! Account representation

use std::fmt;
use std::net::Ipv4Addr;

use crate::AUTH_KEY_SIZE;

/// Telegram datacenter addresses (production)
const DC_ADDRESSES: [(i32, Ipv4Addr, u16); 5] = [
    (1, Ipv4Addr::new(149, 154, 175, 53), 443),
    (2, Ipv4Addr::new(149, 154, 167, 51), 443),
    (3, Ipv4Addr::new(149, 154, 175, 100), 443),
    (4, Ipv4Addr::new(149, 154, 167, 91), 443),
    (5, Ipv4Addr::new(91, 108, 56, 130), 443),
];

/// A Telegram account extracted from tdata
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

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("index", &self.index)
            .field("dc_id", &self.dc_id)
            .field("user_id", &"<redacted>")
            .field("auth_key", &"<redacted>")
            .finish()
    }
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

    /// Get the Telegram user ID.
    ///
    /// Treat account identifiers as private data and avoid logging them.
    pub fn user_id(&self) -> i64 {
        self.user_id
    }

    /// Get the raw auth key bytes.
    ///
    /// This grants access to the Telegram account. Never log, serialize, or expose it.
    pub fn auth_key_bytes(&self) -> &[u8; AUTH_KEY_SIZE] {
        &self.auth_key
    }

    /// Convert to grammers SessionData.
    ///
    /// The returned value contains live authentication credentials and can be imported
    /// into any `grammers` session storage. Never log or expose it.
    pub fn to_grammers_session_data(&self) -> grammers_session::SessionData {
        use grammers_session::{types::DcOption, SessionData};
        use std::net::{SocketAddrV4, SocketAddrV6};

        // Get or create DC option with auth key
        let (ip, port) = DC_ADDRESSES
            .iter()
            .find(|(id, _, _)| *id == self.dc_id)
            .map(|(_, ip, port)| (*ip, *port))
            .unwrap_or((Ipv4Addr::new(149, 154, 167, 51), 443));

        let ipv4 = ip;
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
    fn debug_redacts_account_identity_and_auth_key() {
        let account = Account::new(0, 2, 12_345_678, [0xAB; AUTH_KEY_SIZE]);
        let debug = format!("{account:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("12345678"));
        assert!(!debug.contains("171, 171"));
    }
}
