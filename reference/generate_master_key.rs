//! HARDVAULT — `hardvault keygen` 子命令的核心邏輯參考
//!
//! 輸出 32 bytes 的隨機金鑰，以 base64 編碼後印到 stdout，
//! stderr 印操作說明（這樣 `hardvault keygen > key.txt` 才不會被汙染）。
//!
//! 依賴（在 hardvault crate 的 Cargo.toml）：
//!
//! ```toml
//! [dependencies]
//! aes-gcm = "0.10"   # 已透過 aead 帶入 OsRng + rand_core，不需再加 rand
//! base64  = "0.22"
//! ```
//!
//! 獨立測試（不掛在 hardvault binary 上）：
//!
//! ```bash
//! cargo new --bin keygen-test && cd keygen-test
//! cargo add aes-gcm base64
//! # 將本檔內容貼到 src/main.rs
//! cargo run
//! ```

use aes_gcm::aead::{rand_core::RngCore, OsRng};
use base64::{engine::general_purpose::STANDARD, Engine};

/// AES-256 → 32 bytes
const KEY_LEN: usize = 32;

fn main() {
    let mut key = [0u8; KEY_LEN];
    // OsRng 內部呼叫 OS RNG（Linux: getrandom(2)、Windows: BCryptGenRandom）
    OsRng.fill_bytes(&mut key);

    let b64 = STANDARD.encode(key);

    // stdout：只印金鑰本體，方便 redirect 到檔案或 shell substitution
    println!("{b64}");

    // stderr：印操作說明（不會被 pipe 吃掉）
    eprintln!();
    eprintln!("# ====== 設定方式 ======");
    eprintln!("# Linux / macOS:");
    eprintln!("#   export HARDVAULT_MASTER_KEY=\"{b64}\"");
    eprintln!("#");
    eprintln!("# Windows (CMD):");
    eprintln!("#   setx HARDVAULT_MASTER_KEY \"{b64}\"");
    eprintln!("#");
    eprintln!("# Windows (PowerShell):");
    eprintln!("#   [Environment]::SetEnvironmentVariable(");
    eprintln!("#     'HARDVAULT_MASTER_KEY', '{b64}', 'User')");
    eprintln!();
    eprintln!("# ⚠ 妥善保管，遺失後所有密文無法還原");
    eprintln!("# ⚠ Production / Development 請使用不同金鑰");
    eprintln!("# ⚠ 不要寫進原始碼、Slack、Email、雲端硬碟");

    // 不嚴格要求，但盡力清除：key array 離開 main 後會被覆寫，
    // 但 OS-level swap / core dump 仍可能殘留 → 真實版本需用 zeroize crate。
    // 此處只是 reference，hardvault crate 內部會用 Zeroizing 包裝。
}
