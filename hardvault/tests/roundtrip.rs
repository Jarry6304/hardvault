//! Roundtrip 測試：驗證 encrypt → 拆解 byte layout → decrypt 流程
//!
//! 這個測試非常關鍵 —— 它驗證 Rust 端產出的 byte layout 與 C# 端
//! `GeneratedSecretsProvider.Decrypt` 預期的 layout 完全一致。
//!
//! Layout: `[nonce 12][ciphertext N][tag 16]`

use hardvault::encrypt::{decrypt, encrypt, generate_master_key_b64, load_key_from_b64, KEY_LEN, NONCE_LEN, TAG_LEN};

#[test]
fn full_roundtrip_with_generated_key() {
    let b64 = generate_master_key_b64();
    let key = load_key_from_b64(&b64).unwrap();

    let secrets = [
        "short",
        "a moderately long secret with special chars: !@#$%^&*()",
        "中文機敏值",
        "",
        &"x".repeat(1024),
    ];

    for pt in secrets {
        let blob = encrypt(&key, pt.as_bytes()).unwrap();

        // 驗證 byte layout
        assert_eq!(
            blob.len(),
            NONCE_LEN + pt.len() + TAG_LEN,
            "blob 大小應為 nonce(12) + plaintext({}) + tag(16)",
            pt.len()
        );

        // 驗證解密
        let recovered = decrypt(&key, &blob).unwrap();
        assert_eq!(recovered, pt.as_bytes());
    }
}

#[test]
fn byte_layout_matches_csharp_expectation() {
    // 模擬 C# GeneratedSecretsProvider.Decrypt 拆 blob 的邏輯
    let key = [7u8; KEY_LEN];
    let pt = b"hello";
    let blob = encrypt(&key, pt).unwrap();

    assert!(blob.len() >= NONCE_LEN + TAG_LEN);
    let ct_len = blob.len() - NONCE_LEN - TAG_LEN;
    assert_eq!(ct_len, pt.len(), "AES-GCM ciphertext 與 plaintext 等長");

    // C# 端會這樣拆：
    //   nonce = blob[0..12]
    //   ct    = blob[12..blob.Length-16]
    //   tag   = blob[blob.Length-16..]
    let nonce = &blob[..NONCE_LEN];
    let ct = &blob[NONCE_LEN..blob.len() - TAG_LEN];
    let tag = &blob[blob.len() - TAG_LEN..];

    assert_eq!(nonce.len(), 12);
    assert_eq!(ct.len(), pt.len());
    assert_eq!(tag.len(), 16);

    // 重組 blob 後解密應該成功
    let mut reassembled = Vec::new();
    reassembled.extend_from_slice(nonce);
    reassembled.extend_from_slice(ct);
    reassembled.extend_from_slice(tag);
    assert_eq!(reassembled, blob);

    let recovered = decrypt(&key, &reassembled).unwrap();
    assert_eq!(recovered, pt);
}

#[test]
fn nonce_uniqueness_across_many_calls() {
    let key = [3u8; KEY_LEN];
    let pt = b"x";
    let mut nonces = std::collections::HashSet::new();

    for _ in 0..1000 {
        let blob = encrypt(&key, pt).unwrap();
        let nonce: [u8; 12] = blob[..12].try_into().unwrap();
        assert!(nonces.insert(nonce), "nonce 撞號（隨機性失敗）");
    }
}
