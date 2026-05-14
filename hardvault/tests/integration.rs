//! 整合測試：呼叫 hardvault binary、比對輸出檔
//!
//! 這些測試會用 cargo 建好的 binary 跑真實 CLI flow。

use base64::Engine;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    env!("CARGO_BIN_EXE_hardvault").into()
}

#[test]
fn keygen_prints_44_char_base64() {
    let output = Command::new(bin()).arg("keygen").output().unwrap();
    assert!(output.status.success(), "keygen exit: {:?}", output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let key = stdout.trim();
    assert_eq!(
        key.len(),
        44,
        "32 bytes base64 應為 44 字元，實際: {}",
        key.len()
    );
    assert!(key.ends_with('='), "base64 32 bytes 必有一個 = padding");
}

#[test]
fn keygen_outputs_distinct_keys() {
    let a = Command::new(bin()).arg("keygen").output().unwrap();
    let b = Command::new(bin()).arg("keygen").output().unwrap();
    assert_ne!(a.stdout, b.stdout, "兩次 keygen 必須不同");
}

#[test]
fn build_produces_both_files() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("secrets.toml");
    let out_cs = tmp.path().join("Out.cs");
    let out_json = tmp.path().join("appsettings.json");

    std::fs::write(
        &input,
        r#"
[secrets]
TOKEN = "abc"

[config]
SIZE = "10"
"#,
    )
    .unwrap();

    let key = run_keygen();

    let status = Command::new(bin())
        .args([
            "build",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
            "--out-json",
            out_json.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", &key)
        .output()
        .unwrap();

    assert!(status.status.success(), "build failed: {:?}", status);
    assert!(out_cs.exists(), "out-cs 沒產生");
    assert!(out_json.exists(), "out-json 沒產生");

    let cs = std::fs::read_to_string(&out_cs).unwrap();
    assert!(cs.contains("namespace Hardvault.Security;"));
    assert!(cs.contains(r#"["TOKEN"] = new(true,"#));
    assert!(cs.contains(r#"["SIZE"] = new(false,"#));
    assert!(cs.contains("0x31, 0x30"), "SIZE = \"10\" 應為 0x31 0x30");

    let json = std::fs::read_to_string(&out_json).unwrap();
    assert!(json.contains(r#""Hardvault""#));
    assert!(json.contains(r#""TOKEN""#));
    assert!(json.contains(r#""SIZE""#));
}

#[test]
fn build_creates_parent_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("secrets.toml");
    let out_cs = tmp.path().join("deep/nested/Out.cs");
    let out_json = tmp.path().join("appsettings.json");

    std::fs::write(&input, "[config]\nA = \"1\"\n").unwrap();

    let key = run_keygen();
    let status = Command::new(bin())
        .args([
            "build",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
            "--out-json",
            out_json.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", &key)
        .output()
        .unwrap();

    assert!(status.status.success(), "build failed: {:?}", status);
    assert!(out_cs.exists());
}

#[test]
fn build_fails_without_key() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("secrets.toml");
    let out_cs = tmp.path().join("Out.cs");
    let out_json = tmp.path().join("appsettings.json");
    std::fs::write(&input, "[config]\nA = \"1\"\n").unwrap();

    let output = Command::new(bin())
        .args([
            "build",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
            "--out-json",
            out_json.to_str().unwrap(),
        ])
        .env_remove("HARDVAULT_MASTER_KEY")
        .output()
        .unwrap();

    assert!(!output.status.success(), "缺 key 應該失敗");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("HARDVAULT_MASTER_KEY"),
        "錯誤訊息應提到變數名：{stderr}"
    );
}

#[test]
fn build_fails_with_bad_key_length() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("secrets.toml");
    let out_cs = tmp.path().join("Out.cs");
    let out_json = tmp.path().join("appsettings.json");
    std::fs::write(&input, "[config]\nA = \"1\"\n").unwrap();

    // 16 bytes base64 — 太短
    let bad_key = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);

    let output = Command::new(bin())
        .args([
            "build",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
            "--out-json",
            out_json.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", bad_key)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("32 bytes"));
}

#[test]
fn build_fails_with_invalid_toml() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("secrets.toml");
    let out_cs = tmp.path().join("Out.cs");
    let out_json = tmp.path().join("appsettings.json");
    // 小寫 key 違反 schema
    std::fs::write(&input, "[secrets]\nlowercase = \"x\"\n").unwrap();

    let key = run_keygen();
    let output = Command::new(bin())
        .args([
            "build",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
            "--out-json",
            out_json.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", &key)
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[test]
fn verify_passes_after_build() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("secrets.toml");
    let out_cs = tmp.path().join("Out.cs");
    let out_json = tmp.path().join("appsettings.json");
    std::fs::write(
        &input,
        "[secrets]\nTOKEN = \"x\"\n[config]\nSIZE = \"10\"\n",
    )
    .unwrap();

    let key = run_keygen();

    let build = Command::new(bin())
        .args([
            "build",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
            "--out-json",
            out_json.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", &key)
        .output()
        .unwrap();
    assert!(build.status.success());

    let verify = Command::new(bin())
        .args([
            "verify",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", &key)
        .output()
        .unwrap();
    assert!(verify.status.success(), "verify should pass: {:?}", verify);
}

#[test]
fn verify_fails_when_key_added_after_build() {
    let tmp = tempfile::tempdir().unwrap();
    let input = tmp.path().join("secrets.toml");
    let out_cs = tmp.path().join("Out.cs");
    let out_json = tmp.path().join("appsettings.json");

    std::fs::write(&input, "[config]\nA = \"1\"\n").unwrap();
    let key = run_keygen();

    Command::new(bin())
        .args([
            "build",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
            "--out-json",
            out_json.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", &key)
        .output()
        .unwrap();

    // 修改 secrets.toml 但沒 rebuild
    std::fs::write(&input, "[config]\nA = \"1\"\nB = \"2\"\n").unwrap();

    let verify = Command::new(bin())
        .args([
            "verify",
            "--input",
            input.to_str().unwrap(),
            "--out-cs",
            out_cs.to_str().unwrap(),
        ])
        .env("HARDVAULT_MASTER_KEY", &key)
        .output()
        .unwrap();

    assert!(!verify.status.success(), "verify should catch stale .cs");
    let stderr = String::from_utf8_lossy(&verify.stderr);
    assert!(stderr.contains("B"), "should mention missing key 'B'");
}

fn run_keygen() -> String {
    let out = Command::new(bin()).arg("keygen").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}
