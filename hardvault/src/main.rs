use clap::Parser;
use std::fs;
use std::path::Path;

use hardvault::cli::{Cli, Command};
use hardvault::codegen;
use hardvault::encrypt::{self, KEY_LEN};
use hardvault::error::HardvaultError;
use hardvault::schema::SecretsToml;
use zeroize::Zeroizing;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => keygen(),
        Command::Build {
            input,
            out_cs,
            out_json,
            namespace,
            key_env,
        } => build(&input, &out_cs, &out_json, &namespace, &key_env),
        Command::Verify {
            input,
            out_cs,
            key_env,
        } => verify(&input, &out_cs, &key_env),
        Command::Rotate {
            input,
            out_cs,
            out_json,
            namespace,
            key_env,
            new_key_env,
        } => rotate(
            &input,
            &out_cs,
            &out_json,
            &namespace,
            &key_env,
            &new_key_env,
        ),
    }
}

fn keygen() -> anyhow::Result<()> {
    let b64 = encrypt::generate_master_key_b64();
    // stdout: 只印金鑰本體，方便 redirect
    println!("{b64}");
    // stderr: 操作說明
    eprintln!();
    eprintln!("# === 設定方式 ===");
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
    Ok(())
}

fn read_key_from_env(env_name: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, HardvaultError> {
    let b64 =
        std::env::var(env_name).map_err(|_| HardvaultError::KeyNotSet(env_name.to_string()))?;
    encrypt::load_key_from_b64(&b64)
}

fn build(
    input: &Path,
    out_cs: &Path,
    out_json: &Path,
    namespace: &str,
    key_env: &str,
) -> anyhow::Result<()> {
    let key = read_key_from_env(key_env)?;

    let content =
        fs::read_to_string(input).map_err(|e| HardvaultError::ReadFile(input.to_path_buf(), e))?;
    let toml = SecretsToml::parse(&content)?;

    let cs = codegen::build_cs(&toml, &key, namespace)?;
    let app = codegen::build_appsettings(&toml);
    let json = serde_json::to_string_pretty(&app).map_err(HardvaultError::JsonSerialize)?;

    if let Some(parent) = out_cs.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| HardvaultError::WriteFile(parent.to_path_buf(), e))?;
        }
    }
    if let Some(parent) = out_json.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| HardvaultError::WriteFile(parent.to_path_buf(), e))?;
        }
    }

    fs::write(out_cs, cs).map_err(|e| HardvaultError::WriteFile(out_cs.to_path_buf(), e))?;
    fs::write(out_json, json).map_err(|e| HardvaultError::WriteFile(out_json.to_path_buf(), e))?;

    eprintln!("✓ {}", out_cs.display());
    eprintln!("✓ {}", out_json.display());
    eprintln!(
        "  {} secret(s), {} config(s)",
        toml.secrets.len(),
        toml.config.len()
    );
    Ok(())
}

fn verify(input: &Path, out_cs: &Path, key_env: &str) -> anyhow::Result<()> {
    let _key = read_key_from_env(key_env)?;

    let content =
        fs::read_to_string(input).map_err(|e| HardvaultError::ReadFile(input.to_path_buf(), e))?;
    let toml = SecretsToml::parse(&content)?;

    if !out_cs.exists() {
        anyhow::bail!("{} 不存在，請先執行 `hardvault build`", out_cs.display());
    }

    let cs = fs::read_to_string(out_cs)
        .map_err(|e| HardvaultError::ReadFile(out_cs.to_path_buf(), e))?;

    let mut missing = Vec::new();
    for k in toml.secrets.keys().chain(toml.config.keys()) {
        let needle = format!(r#"["{k}"]"#);
        if !cs.contains(&needle) {
            missing.push(k.clone());
        }
    }

    if !missing.is_empty() {
        anyhow::bail!(
            "下列 KEY 在 {} 中找不到，請重新 `hardvault build`：{}",
            out_cs.display(),
            missing.join(", ")
        );
    }

    eprintln!(
        "✓ {} ↔ {} 的 KEY 清單一致 ({} secret + {} config)",
        input.display(),
        out_cs.display(),
        toml.secrets.len(),
        toml.config.len()
    );
    Ok(())
}

fn rotate(
    input: &Path,
    out_cs: &Path,
    out_json: &Path,
    namespace: &str,
    key_env: &str,
    new_key_env: &str,
) -> anyhow::Result<()> {
    if key_env == new_key_env {
        anyhow::bail!("--key-env 與 --new-key-env 不能指向同一個環境變數（{key_env}）");
    }

    let old_key = read_key_from_env(key_env)?;
    let new_key = read_key_from_env(new_key_env)?;
    if old_key.as_slice() == new_key.as_slice() {
        anyhow::bail!("新舊金鑰內容相同（{key_env} 與 {new_key_env}），rotate 沒有意義");
    }
    // 顯式 drop 舊 key — 不需要它，避免額外停留
    drop(old_key);
    drop(new_key);

    // 委派給 build，用新 env 重新加密
    build(input, out_cs, out_json, namespace, new_key_env)?;

    eprintln!();
    eprintln!("🔄 Rotate 完成。下一步：");
    eprintln!("  1. 更新所有部署環境的 HARDVAULT_MASTER_KEY 為新值");
    eprintln!("  2. 重新編譯與部署 C# 專案");
    eprintln!("  3. 舊金鑰視為已洩漏，銷毀並更換");
    Ok(())
}
