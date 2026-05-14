use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HardvaultError {
    #[error("環境變數 {0} 未設定。執行 `hardvault keygen` 產生並設定。")]
    KeyNotSet(String),

    #[error("HARDVAULT_MASTER_KEY 不是合法的 base64 字串")]
    KeyNotBase64(#[source] base64::DecodeError),

    #[error("HARDVAULT_MASTER_KEY 必須為 32 bytes (AES-256)，目前 {0} bytes")]
    KeyWrongLength(usize),

    #[error("讀取檔案 {0} 失敗")]
    ReadFile(PathBuf, #[source] std::io::Error),

    #[error("寫入檔案 {0} 失敗")]
    WriteFile(PathBuf, #[source] std::io::Error),

    #[error("解析 TOML 失敗")]
    TomlParse(#[from] toml::de::Error),

    #[error("secrets.toml schema 驗證失敗：{0}")]
    Schema(String),

    #[error("AES-GCM 加解密失敗")]
    Crypto,

    #[error("JSON 序列化失敗")]
    JsonSerialize(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, HardvaultError>;
