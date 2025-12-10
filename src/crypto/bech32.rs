//! Bech32 encoding/decoding for Celereum addresses
//!
//! Based on BIP-173 specification for human-readable addresses.
//! Format: cel1 + data + checksum
//! Example: cel1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
//!
//! # Security Features
//! - BCH polynomial checksum (detects up to 4 errors)
//! - No confusing characters (0/O/I/l excluded)
//! - Case-insensitive (rejects mixed case)
//! - Network prefix verification (only "cel" accepted)

use std::fmt;

/// Bech32 character set (lowercase only, no confusing chars)
const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Human-readable part for Celereum
pub const CEL_HRP: &str = "cel";

/// Address length in bytes (32 bytes for SHA3-256 hash)
pub const ADDRESS_BYTES: usize = 32;

/// Generator polynomial for checksum
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

/// Bech32 error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bech32Error {
    /// Invalid character in address
    InvalidCharacter(char),
    /// Mixed case (BIP-173 violation)
    MixedCase,
    /// Invalid HRP (not "cel")
    InvalidHrp(String),
    /// Invalid checksum
    InvalidChecksum,
    /// Invalid data length
    InvalidLength { expected: usize, got: usize },
    /// Invalid separator position
    InvalidSeparator,
    /// Address too long (max 90 chars)
    TooLong,
    /// Conversion error
    ConversionError,
}

impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(c) => write!(f, "Invalid Bech32 character: {}", c),
            Self::MixedCase => write!(f, "Mixed case in Bech32 address (BIP-173 violation)"),
            Self::InvalidHrp(hrp) => write!(f, "Invalid HRP: expected 'cel', got '{}'", hrp),
            Self::InvalidChecksum => write!(f, "Invalid Bech32 checksum"),
            Self::InvalidLength { expected, got } => {
                write!(f, "Invalid data length: expected {} bytes, got {}", expected, got)
            }
            Self::InvalidSeparator => write!(f, "Invalid separator position"),
            Self::TooLong => write!(f, "Address too long (max 90 characters)"),
            Self::ConversionError => write!(f, "Bit conversion error"),
        }
    }
}

impl std::error::Error for Bech32Error {}

/// Compute Bech32 polymod checksum
fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (v as u32);
        for (i, &gen) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

/// Expand HRP for checksum computation
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut ret = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.chars() {
        ret.push((c as u8) >> 5);
    }
    ret.push(0);
    for c in hrp.chars() {
        ret.push((c as u8) & 31);
    }
    ret
}

/// Verify Bech32 checksum
fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    polymod(&values) == 1
}

/// Create Bech32 checksum
fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let polymod = polymod(&values) ^ 1;
    let mut ret = [0u8; 6];
    for i in 0..6 {
        ret[i] = ((polymod >> (5 * (5 - i))) & 31) as u8;
    }
    ret
}

/// Convert between bit sizes (for 8-bit to 5-bit conversion)
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, Bech32Error> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv = (1u32 << to_bits) - 1;

    for &value in data {
        let value = value as u32;
        if value >> from_bits != 0 {
            return Err(Bech32Error::ConversionError);
        }
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            ret.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err(Bech32Error::ConversionError);
    }

    Ok(ret)
}

/// Encode bytes to Bech32 address with cel1 prefix
///
/// # Arguments
/// * `data` - Raw address bytes (must be exactly 32 bytes)
///
/// # Returns
/// Bech32 encoded address (e.g., cel1qpzry9x8gf2tvdw0s3jn54khce6mua7l...)
///
/// # Errors
/// Returns error if data is not exactly 32 bytes
pub fn encode_cel_address(data: &[u8; ADDRESS_BYTES]) -> String {
    // Convert 8-bit bytes to 5-bit groups
    let converted = convert_bits(data, 8, 5, true)
        .expect("32-byte input always converts successfully");

    // Create checksum
    let checksum = create_checksum(CEL_HRP, &converted);

    // Build result string
    let mut result = String::with_capacity(CEL_HRP.len() + 1 + converted.len() + 6);
    result.push_str(CEL_HRP);
    result.push('1');

    for &d in converted.iter().chain(checksum.iter()) {
        result.push(CHARSET[d as usize] as char);
    }

    result
}

/// Decode Bech32 cel1 address to raw bytes
///
/// # Arguments
/// * `address` - Bech32 encoded address
///
/// # Returns
/// Raw address bytes (32 bytes) or error if invalid
///
/// # Security
/// - Rejects mixed case (BIP-173 requirement)
/// - Verifies checksum
/// - Validates HRP is exactly "cel"
/// - Validates output is exactly 32 bytes
pub fn decode_cel_address(address: &str) -> Result<[u8; ADDRESS_BYTES], Bech32Error> {
    // Security: Reject mixed case (BIP-173 requirement)
    let has_lower = address.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = address.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }

    // Lowercase for processing
    let lower = address.to_lowercase();

    // Check length
    if lower.len() > 90 {
        return Err(Bech32Error::TooLong);
    }

    // Check prefix
    if !lower.starts_with(&format!("{}1", CEL_HRP)) {
        return Err(Bech32Error::InvalidHrp(
            lower.chars().take(3).collect()
        ));
    }

    // Find separator (the '1' after HRP)
    let sep_pos = lower.rfind('1').ok_or(Bech32Error::InvalidSeparator)?;
    if sep_pos < 1 || sep_pos + 7 > lower.len() {
        return Err(Bech32Error::InvalidSeparator);
    }

    let hrp = &lower[..sep_pos];

    // Security: HRP must be exactly 'cel'
    if hrp != CEL_HRP {
        return Err(Bech32Error::InvalidHrp(hrp.to_string()));
    }

    let data_str = &lower[sep_pos + 1..];

    // Decode data part
    let mut data = Vec::with_capacity(data_str.len());
    for c in data_str.chars() {
        let pos = CHARSET.iter().position(|&x| x as char == c)
            .ok_or(Bech32Error::InvalidCharacter(c))?;
        data.push(pos as u8);
    }

    // Verify checksum
    if !verify_checksum(hrp, &data) {
        return Err(Bech32Error::InvalidChecksum);
    }

    // Remove checksum (last 6 characters)
    let data_without_checksum = &data[..data.len() - 6];

    // Convert 5-bit back to 8-bit
    let bytes = convert_bits(data_without_checksum, 5, 8, false)?;

    // Security: Verify output is exactly 32 bytes
    if bytes.len() != ADDRESS_BYTES {
        return Err(Bech32Error::InvalidLength {
            expected: ADDRESS_BYTES,
            got: bytes.len(),
        });
    }

    let mut result = [0u8; ADDRESS_BYTES];
    result.copy_from_slice(&bytes);
    Ok(result)
}

/// Validate a Celereum Bech32 address
///
/// # Arguments
/// * `address` - Address to validate
///
/// # Returns
/// true if valid cel1 address
pub fn is_valid_cel_address(address: &str) -> bool {
    decode_cel_address(address).is_ok()
}

/// Check if address is in cel1 Bech32 format
pub fn is_cel1_format(address: &str) -> bool {
    address.to_lowercase().starts_with("cel1")
}

/// Check if address is in Base58 format (legacy)
pub fn is_base58_format(address: &str) -> bool {
    // Base58 uses alphanumeric chars except 0, O, I, l
    !address.starts_with("cel1") &&
    address.chars().all(|c| {
        matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
    })
}

/// Parse address from either cel1 Bech32 or legacy Base58 format
///
/// # Arguments
/// * `address` - Address string in either format
///
/// # Returns
/// Raw 32-byte address or error
pub fn parse_address(address: &str) -> Result<[u8; ADDRESS_BYTES], Bech32Error> {
    if is_cel1_format(address) {
        decode_cel_address(address)
    } else if is_base58_format(address) {
        // Legacy Base58 support
        bs58::decode(address)
            .into_vec()
            .map_err(|_| Bech32Error::ConversionError)
            .and_then(|bytes| {
                if bytes.len() != ADDRESS_BYTES {
                    Err(Bech32Error::InvalidLength {
                        expected: ADDRESS_BYTES,
                        got: bytes.len(),
                    })
                } else {
                    let mut result = [0u8; ADDRESS_BYTES];
                    result.copy_from_slice(&bytes);
                    Ok(result)
                }
            })
    } else {
        Err(Bech32Error::InvalidHrp(address.chars().take(4).collect()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];

        let encoded = encode_cel_address(&original);
        assert!(encoded.starts_with("cel1"));

        let decoded = decode_cel_address(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_mixed_case_rejected() {
        let valid = "cel1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
        // Create mixed case version
        let mixed = "CEL1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";

        assert!(matches!(
            decode_cel_address(mixed),
            Err(Bech32Error::MixedCase)
        ));
    }

    #[test]
    fn test_invalid_checksum() {
        // Valid address with last char changed
        let invalid = "cel1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxa";

        assert!(matches!(
            decode_cel_address(invalid),
            Err(Bech32Error::InvalidChecksum)
        ));
    }

    #[test]
    fn test_invalid_hrp() {
        let invalid = "btc1qpzry9x8gf2tvdw0s3jn54khce6mua7l";

        assert!(matches!(
            decode_cel_address(invalid),
            Err(Bech32Error::InvalidHrp(_))
        ));
    }

    #[test]
    fn test_is_cel1_format() {
        assert!(is_cel1_format("cel1qpzry9x8gf2tvdw0s3jn54khce6mua7l"));
        assert!(is_cel1_format("CEL1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"));
        assert!(!is_cel1_format("ABC123XYZ"));
    }

    #[test]
    fn test_parse_address_cel1() {
        let bytes = [0u8; 32];
        let cel1 = encode_cel_address(&bytes);
        let parsed = parse_address(&cel1).unwrap();
        assert_eq!(bytes, parsed);
    }
}
