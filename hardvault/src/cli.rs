use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "hardvault",
    version,
    about = "兩層防線：燒入 exe 的密文 + 外部 HARDVAULT_MASTER_KEY",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// 從 secrets.toml 產生 GeneratedSecrets.cs 與 appsettings.json
    Build {
        /// secrets.toml 的路徑
        #[arg(long, default_value = "secrets.toml")]
        input: PathBuf,

        /// 產生的 C# 檔案路徑（會 mkdir -p 父目錄）
        #[arg(
            long = "out-cs",
            default_value = "Infrastructure/Security/GeneratedSecrets.cs"
        )]
        out_cs: PathBuf,

        /// 產生的 appsettings.json 路徑
        #[arg(long = "out-json", default_value = "appsettings.json")]
        out_json: PathBuf,

        /// 產生的 C# 命名空間
        #[arg(long, default_value = "Hardvault.Security")]
        namespace: String,

        /// 讀取 master key 的環境變數名稱（不接受直接傳入金鑰）
        #[arg(long = "key-env", default_value = "HARDVAULT_MASTER_KEY")]
        key_env: String,
    },

    /// 產生 32-byte 隨機 HARDVAULT_MASTER_KEY 並以 base64 印至 stdout
    Keygen,

    /// 檢查 secrets.toml 與已產生的 .cs 的 KEY 清單是否一致
    Verify {
        #[arg(long, default_value = "secrets.toml")]
        input: PathBuf,

        #[arg(
            long = "out-cs",
            default_value = "Infrastructure/Security/GeneratedSecrets.cs"
        )]
        out_cs: PathBuf,

        #[arg(long = "key-env", default_value = "HARDVAULT_MASTER_KEY")]
        key_env: String,
    },

    /// 用新金鑰重新加密 secrets.toml，產生新的 GeneratedSecrets.cs
    ///
    /// 設定流程：
    ///   export HARDVAULT_MASTER_KEY=<舊金鑰>
    ///   export HARDVAULT_NEW_KEY=$(hardvault keygen | head -1)
    ///   hardvault rotate
    Rotate {
        #[arg(long, default_value = "secrets.toml")]
        input: PathBuf,

        #[arg(
            long = "out-cs",
            default_value = "Infrastructure/Security/GeneratedSecrets.cs"
        )]
        out_cs: PathBuf,

        #[arg(long = "out-json", default_value = "appsettings.json")]
        out_json: PathBuf,

        #[arg(long, default_value = "Hardvault.Security")]
        namespace: String,

        /// 舊金鑰所在的環境變數（rotate 完應銷毀此值）
        #[arg(long = "key-env", default_value = "HARDVAULT_MASTER_KEY")]
        key_env: String,

        /// 新金鑰所在的環境變數
        #[arg(long = "new-key-env", default_value = "HARDVAULT_NEW_KEY")]
        new_key_env: String,
    },
}
