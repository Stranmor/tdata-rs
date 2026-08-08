//! QDataStream parser implementation
//!
//! Implements reading Qt's QDataStream binary format (version Qt_5_1 = 14).
//! All integers are Big Endian. Strings are UTF-16 BE.

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};

use crate::{Error, Result};

/// Qt DataStream version used by Telegram Desktop
pub const QT_VERSION_5_1: u32 = 14;

/// Marker for null QByteArray/QString
const NULL_MARKER: u32 = 0xFFFFFFFF;

/// Marker for extended 64-bit length (Qt 6.7+, not used in tdata)
const EXTENDED_LENGTH_MARKER: u32 = 0xFFFFFFFE;

/// QDataStream reader for parsing Qt binary serialization format
pub struct QDataStream<'a> {
    cursor: Cursor<&'a [u8]>,
    version: u32,
}

impl<'a> QDataStream<'a> {
    /// Create a new QDataStream reader with Qt 5.1 version
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(data),
            version: QT_VERSION_5_1,
        }
    }

    /// Create a new QDataStream reader with specified version
    pub fn with_version(data: &'a [u8], version: u32) -> Self {
        Self {
            cursor: Cursor::new(data),
            version,
        }
    }

    /// Get the Qt version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Get current position in the stream
    pub fn position(&self) -> u64 {
        self.cursor.position()
    }

    /// Check if we've reached the end of the stream
    pub fn at_end(&self) -> bool {
        self.cursor.position() >= self.cursor.get_ref().len() as u64
    }

    /// Get remaining bytes count
    pub fn remaining(&self) -> usize {
        let pos = self.cursor.position() as usize;
        let len = self.cursor.get_ref().len();
        len.saturating_sub(pos)
    }

    /// Skip n bytes
    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.cursor
            .seek(SeekFrom::Current(n as i64))
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })?;
        Ok(())
    }

    /// Read a single byte (quint8)
    pub fn read_u8(&mut self) -> Result<u8> {
        self.cursor.read_u8().map_err(|_| Error::UnexpectedEof {
            offset: self.position(),
        })
    }

    /// Read a signed 8-bit integer (qint8)
    pub fn read_i8(&mut self) -> Result<i8> {
        self.cursor.read_i8().map_err(|_| Error::UnexpectedEof {
            offset: self.position(),
        })
    }

    /// Read an unsigned 16-bit integer (quint16) - Big Endian
    pub fn read_u16(&mut self) -> Result<u16> {
        self.cursor
            .read_u16::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read a signed 16-bit integer (qint16) - Big Endian
    pub fn read_i16(&mut self) -> Result<i16> {
        self.cursor
            .read_i16::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read an unsigned 32-bit integer (quint32) - Big Endian
    pub fn read_u32(&mut self) -> Result<u32> {
        self.cursor
            .read_u32::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read a signed 32-bit integer (qint32) - Big Endian
    pub fn read_i32(&mut self) -> Result<i32> {
        self.cursor
            .read_i32::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read an unsigned 64-bit integer (quint64) - Big Endian
    pub fn read_u64(&mut self) -> Result<u64> {
        self.cursor
            .read_u64::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read a signed 64-bit integer (qint64) - Big Endian
    pub fn read_i64(&mut self) -> Result<i64> {
        self.cursor
            .read_i64::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read a boolean value
    pub fn read_bool(&mut self) -> Result<bool> {
        Ok(self.read_u8()? != 0)
    }

    /// Read a 32-bit float - Big Endian
    pub fn read_f32(&mut self) -> Result<f32> {
        self.cursor
            .read_f32::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read a 64-bit double - Big Endian
    pub fn read_f64(&mut self) -> Result<f64> {
        self.cursor
            .read_f64::<BigEndian>()
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })
    }

    /// Read raw bytes of specified length
    pub fn read_raw(&mut self, len: usize) -> Result<Vec<u8>> {
        if self.remaining() < len {
            return Err(Error::UnexpectedEof {
                offset: self.position(),
            });
        }

        let mut buf = vec![0u8; len];
        self.cursor
            .read_exact(&mut buf)
            .map_err(|_| Error::UnexpectedEof {
                offset: self.position(),
            })?;
        Ok(buf)
    }

    /// Read a QByteArray
    ///
    /// Wire format:
    /// - 4 bytes: length (quint32 BE)
    ///   - 0xFFFFFFFF = null QByteArray (returns empty vec)
    ///   - 0xFFFFFFFE = extended 64-bit length (followed by quint64)
    /// - N bytes: raw data
    pub fn read_qbytearray(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()?;

        match len {
            NULL_MARKER => Ok(Vec::new()),
            EXTENDED_LENGTH_MARKER => {
                // Extended 64-bit length (Qt 6.7+)
                let real_len = self.read_u64()? as usize;
                self.read_raw(real_len)
            }
            _ => self.read_raw(len as usize),
        }
    }

    /// Read a QString
    ///
    /// Wire format:
    /// - 4 bytes: length in BYTES (not chars!) of UTF-16 data
    ///   - 0xFFFFFFFF = null QString (returns empty string)
    /// - N bytes: UTF-16 Big Endian encoded characters
    pub fn read_qstring(&mut self) -> Result<String> {
        let byte_len = self.read_u32()?;

        if byte_len == NULL_MARKER {
            return Ok(String::new());
        }

        if byte_len % 2 != 0 {
            return Err(Error::qdatastream("QString byte length is not even"));
        }

        let char_count = (byte_len / 2) as usize;
        let mut utf16: Vec<u16> = Vec::with_capacity(char_count);

        for _ in 0..char_count {
            utf16.push(self.read_u16()?);
        }

        String::from_utf16(&utf16).map_err(|_| Error::InvalidUtf16)
    }

    /// Read a length-prefixed C string (writeBytes format)
    ///
    /// Wire format:
    /// - 4 bytes: length including null terminator
    /// - N bytes: string data including null terminator
    pub fn read_cstring(&mut self) -> Result<String> {
        let data = self.read_qbytearray()?;

        // Remove null terminator if present
        let data = if data.last() == Some(&0) {
            &data[..data.len() - 1]
        } else {
            &data[..]
        };

        String::from_utf8(data.to_vec())
            .map_err(|_| Error::qdatastream("invalid UTF-8 in C string"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u32() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut stream = QDataStream::new(&data);
        assert_eq!(stream.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_i32() {
        let data = [0xFF, 0xFF, 0xFF, 0xFE]; // -2 in big endian
        let mut stream = QDataStream::new(&data);
        assert_eq!(stream.read_i32().unwrap(), -2);
    }

    #[test]
    fn test_read_qbytearray() {
        // Length = 4, data = [0x01, 0x02, 0x03, 0x04]
        let data = [0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        let mut stream = QDataStream::new(&data);
        assert_eq!(
            stream.read_qbytearray().unwrap(),
            vec![0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn test_read_null_qbytearray() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut stream = QDataStream::new(&data);
        assert!(stream.read_qbytearray().unwrap().is_empty());
    }

    #[test]
    fn test_read_qstring() {
        // "Hi" in UTF-16 BE: length = 4 bytes, 'H' = 0x0048, 'i' = 0x0069
        let data = [0x00, 0x00, 0x00, 0x04, 0x00, 0x48, 0x00, 0x69];
        let mut stream = QDataStream::new(&data);
        assert_eq!(stream.read_qstring().unwrap(), "Hi");
    }

    #[test]
    fn test_read_null_qstring() {
        let data = [0xFF, 0xFF, 0xFF, 0xFF];
        let mut stream = QDataStream::new(&data);
        assert!(stream.read_qstring().unwrap().is_empty());
    }

    #[test]
    fn test_position_and_remaining() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut stream = QDataStream::new(&data);

        assert_eq!(stream.position(), 0);
        assert_eq!(stream.remaining(), 5);

        stream.read_u8().unwrap();
        assert_eq!(stream.position(), 1);
        assert_eq!(stream.remaining(), 4);

        stream.skip(2).unwrap();
        assert_eq!(stream.position(), 3);
        assert_eq!(stream.remaining(), 2);
    }

    #[test]
    fn test_at_end() {
        let data = [0x01, 0x02];
        let mut stream = QDataStream::new(&data);

        assert!(!stream.at_end());
        stream.read_u16().unwrap();
        assert!(stream.at_end());
    }
}
