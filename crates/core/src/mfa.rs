//! Multi-Factor Authentication (MFA) utilities using Time-Based One-Time Passwords (TOTP).
//! Implements Base32 encoding/decoding and RFC 6238 TOTP code generation and verification.

use rand::RngExt;
use ring::hmac;

/// Decodes a RFC 4648 compliant Base32 string back into raw bytes.
/// Returns `None` if the input contains invalid characters or padding.
pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let input = input.trim().to_ascii_uppercase();
    let mut bytes = Vec::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }
        let val = match c {
            'A'..='Z' => c as u8 - b'A',
            '2'..='7' => c as u8 - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | val as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }
    Some(bytes)
}

/// Encodes raw bytes into an RFC 4648 compliant Base32 string with padding.
/// Converts every 5 bits of data into a Base32 character.
pub fn encode_base32(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            result.push(alphabet[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        result.push(alphabet[idx] as char);
    }
    while !result.len().is_multiple_of(8) {
        result.push('=');
    }
    result
}

/// Generates a new cryptographically secure 160-bit random Base32 secret key.
/// Commonly used as the shared secret key between the authenticator app and the server.
pub fn generate_mfa_secret() -> String {
    let mut bytes = [0u8; 20]; // 160 bits
    rand::rng().fill(&mut bytes);
    encode_base32(&bytes)
}

/// Generates a 6-digit TOTP code for a specific time step using HMAC-SHA1.
/// Implements RFC 6238 dynamic truncation of HMAC hash results.
///
/// # Parameters
/// - `secret_bytes`: The decoded raw shared secret bytes.
/// - `time_step`: The count of 30-second intervals elapsed since UNIX epoch.
///
/// # Returns
/// A 6-digit string representation of the code (padded with zeros).
pub fn generate_totp_code(secret_bytes: &[u8], time_step: u64) -> String {
    let msg = time_step.to_be_bytes();
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret_bytes);
    let tag = hmac::sign(&key, &msg);
    let hash = tag.as_ref();

    let offset = (hash[hash.len() - 1] & 0x0F) as usize;
    let binary = ((hash[offset] & 0x7F) as u32) << 24
        | (hash[offset + 1] as u32) << 16
        | (hash[offset + 2] as u32) << 8
        | (hash[offset + 3] as u32);

    let code = binary % 1_000_000;
    format!("{:06}", code)
}

/// Verifies a user-supplied TOTP code against a Base32 secret.
/// Accommodates a clock drift window of ±1 step (30 seconds) on client devices.
///
/// # Parameters
/// - `secret`: Base32 encoded shared secret.
/// - `code`: The 6-digit TOTP code to check.
///
/// # Returns
/// `true` if the code matches any of the steps in the allowed window, `false` otherwise.
pub fn verify_totp(secret: &str, code: &str) -> bool {
    let secret_bytes = match decode_base32(secret) {
        Some(b) => b,
        None => return false,
    };

    let current_time = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => return false,
    };

    let step = current_time / 30;

    // Check drift of -1, 0, and +1 steps (30 second intervals)
    for s in (step.saturating_sub(1))..=(step + 1) {
        if generate_totp_code(&secret_bytes, s) == code {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_codec() {
        let original = b"Hello, World!";
        let encoded = encode_base32(original);
        let decoded = decode_base32(&encoded).unwrap();
        assert_eq!(original.as_ref(), decoded.as_slice());
    }

    #[test]
    fn test_totp_generation_and_verification() {
        let secret = generate_mfa_secret();
        let secret_bytes = decode_base32(&secret).unwrap();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let step = current_time / 30;

        let code = generate_totp_code(&secret_bytes, step);
        assert!(verify_totp(&secret, &code));
        assert!(!verify_totp(&secret, "000000"));
    }
}
