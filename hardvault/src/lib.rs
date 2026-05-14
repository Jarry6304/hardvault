//! HARDVAULT — 將 C# 設定值加密後燒入 exe 的 codegen 工具
//!
//! 模組對外公開供整合測試與外部 reuse；CLI 入口在 main.rs。

pub mod cli;
pub mod codegen;
pub mod encrypt;
pub mod error;
pub mod parse_cs;
pub mod schema;
