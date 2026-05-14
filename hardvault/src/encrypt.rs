use crate::error::{HardvaultError, Result};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

/// AES-256 金鑰長度
pub const KEY_LEN: usize = 32;
/// AES-GCM 標準 nonce 長度
pub const NONCE_LEN: usize = 12;
/// AES-GCM 認證 tag 長度
pub const TAG_LEN: usize = 16;
/// nonce + tag overhead
pub const OVERHEAD_LEN: usize = NONCE_LEN + TAG_LEN;

/// 從 base64 載入 32-byte key，包成 Zeroizing 在離開作用域時自動清除。
pub fn load_key_from_b64(b64: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let raw = STANDARD
        .decode(b64.trim())
        .map_err(HardvaultError::KeyNotBase64)?;
    if raw.len() != KEY_LEN {
        return Err(HardvaultError::KeyWrongLength(raw.len()));
    }
    let mut arr = Zeroizing::new([0u8; KEY_LEN]);
    arr.copy_from_slice(&raw);
    Ok(arr)
}

/// 產生 32 bytes 隨機金鑰並 base64 編碼
pub fn generate_master_key_b64() -> String {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    rand::rngs::OsRng.fill_bytes(&mut *key);
    STANDARD.encode(*key)
}

/// 加密 plaintext → blob: `[nonce 12][ciphertext N][tag 16]`
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct_and_tag = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| HardvaultError::Crypto)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct_and_tag.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct_and_tag);
    Ok(out)
}

/// 解密 `[nonce 12][ciphertext N][tag 16]` → plaintext
///
/// 主要用於測試與 `hardvault verify`。實際 runtime 解密由 C# 端執行。
pub fn decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < OVERHEAD_LEN {
        return Err(HardvaultError::Crypto);
    }
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let ct_and_tag = &blob[NONCE_LEN..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(nonce, ct_and_tag)
        .map_err(|_| HardvaultError::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_basic() {
        let key = [42u8; KEY_LEN];
        let pt = b"Hello, HARDVAULT!";
        let blob = encrypt(&key, pt).unwrap();
        assert_eq!(blob.len(), NONCE_LEN + pt.len() + TAG_LEN);
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(&recovered, pt);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let key = [42u8; KEY_LEN];
        let blob = encrypt(&key, b"").unwrap();
        assert_eq!(blob.len(), NONCE_LEN + TAG_LEN);
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn nonce_differs_per_call() {
        let key = [42u8; KEY_LEN];
        let pt = b"same plaintext";
        let a = encrypt(&key, pt).unwrap();
        let b = encrypt(&key, pt).unwrap();
        assert_ne!(a, b, "nonce 必須每次隨機");
        // 但兩者解密回同樣的明文
        assert_eq!(decrypt(&key, &a).unwrap(), decrypt(&key, &b).unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [1u8; KEY_LEN];
        let key2 = [2u8; KEY_LEN];
        let blob = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &blob).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let key = [1u8; KEY_LEN];
        let mut blob = encrypt(&key, b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decrypt(&key, &blob).is_err());
    }

    #[test]
    fn tampered_nonce_fails() {
        let key = [1u8; KEY_LEN];
        let mut blob = encrypt(&key, b"secret").unwrap();
        blob[0] ^= 0x01;
        assert!(decrypt(&key, &blob).is_err());
    }

    #[test]
    fn truncated_blob_fails() {
        let key = [1u8; KEY_LEN];
        let blob = encrypt(&key, b"secret").unwrap();
        assert!(decrypt(&key, &blob[..OVERHEAD_LEN - 1]).is_err());
    }

    #[test]
    fn keygen_roundtrip() {
        let b64 = generate_master_key_b64();
        // 32 bytes base64 with padding = 44 chars
        assert_eq!(b64.len(), 44);
        let loaded = load_key_from_b64(&b64).unwrap();
        assert_eq!(loaded.len(), KEY_LEN);
    }

    #[test]
    fn load_rejects_wrong_length() {
        // 16 bytes base64 ≠ 32 bytes
        let short = STANDARD.encode([0u8; 16]);
        assert!(load_key_from_b64(&short).is_err());
    }

    #[test]
    fn load_rejects_bad_base64() {
        assert!(load_key_from_b64("not!valid_base64!").is_err());
    }

    #[test]
    fn load_tolerates_whitespace() {
        let b64 = generate_master_key_b64();
        let padded = format!("  {b64}\n");
        assert!(load_key_from_b64(&padded).is_ok());
    }
}
