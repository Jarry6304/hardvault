# Changelog

本檔記錄 HARDVAULT 的所有可見變更。

格式參考 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，
版本號遵循 [Semantic Versioning](https://semver.org/spec/v2.0.0.html)。

---

## [Unreleased]

_目前無未發布變更。_

---

## [0.1.0] - 2026-05-14

首次正式公開發布。

### Added

#### Rust CLI（`hardvault` crate）

- `hardvault build`：從 `secrets.toml` 產生 `GeneratedSecrets.cs` 與 `appsettings.json`
- `hardvault keygen`：產生 32 bytes 隨機 `HARDVAULT_MASTER_KEY`（base64）
- `hardvault verify`：比對 `secrets.toml` 與 `GeneratedSecrets.cs` 的 KEY 清單
- `hardvault verify --decrypt`：實際解密驗證每筆密文，比對明文 config bytes，
  偵測 `.cs` 內有但 `secrets.toml` 沒有的 stale KEY
- `hardvault rotate`：用新金鑰重新加密所有密文，提示部署輪替步驟
- `src/parse_cs.rs` 模組：手寫 .cs 解析器（不引 regex crate），
  提取每筆 entry 的 KEY / encrypted / bytes（供 `verify --decrypt` 使用）
- 加密格式：AES-256-GCM、每次加密重新產生 12-byte nonce、16-byte tag
- TOML schema 嚴格驗證：KEY 命名 `^[A-Z][A-Z0-9_]*$`，跨區段重複偵測
- `Zeroizing<T>` RAII 保護金鑰；`SecretsToml` Drop 時自動 zeroize
- Release profile：strip + LTO + panic=abort

#### C# Sample（`sample/Hardvault.Sample`）

- `Hardvault.Sample.csproj` 含 `HardvaultBuild` MSBuild Target（自動觸發 `hardvault build`）
- `Program.cs`、`Services/NotificationService.cs` 示範用法
- 透過 `<Compile Include Link>` 從 `reference/` 引用 `GeneratedSecretsProvider`（單一來源）

#### C# Reference 實作（`reference/`）

- `GeneratedSecretsProvider.cs`：含 `ISecretProvider`、`SecretValue: IDisposable`、
  `GeneratedSecretsProvider`。string 與 byte[] 兩條 API 兼顧便利與安全
- `csproj-target.xml`：MSBuild Target 整合範本
- `hardvault_cli_notes.md`：Rust CLI 設計筆記
- `generate_master_key.rs`：keygen 邏輯參考

#### CI / CD

- `.github/workflows/ci.yml`：rust-lint、rust-test matrix（ubuntu/macos/windows）、
  cargo-audit CVE 掃描、dotnet-sample e2e（含解密 + 失敗驗證）、all-checks-pass gate
- `.github/workflows/release.yml`：tag 觸發、4 platform binary（linux/darwin x2/windows）、
  含 sha256，自動發 GitHub Release
- `.github/dependabot.yml`：weekly 更新 Rust crate 與 GitHub Actions 依賴

#### 文件

- `README.md`、`README.en.md`：雙語完整使用文件
- `SKILL.md`：給 AI agent 的精簡規格
- `docs/ARCHITECTURE.md`：每個設計決策的理由
- `docs/THREAT-MODEL.md`：STRIDE 系統化威脅分析
- `CHANGELOG.md`：本檔，遵循 Keep a Changelog 格式
- `CONTRIBUTING.md`：GitHub UI 自動偵測的快速貢獻入口

### Security

- CLI **絕不接受** `--master-key` 旗標，金鑰只從環境變數讀取
  （防 shell history / process list / CI log 洩漏）
- `secrets.toml`、`GeneratedSecrets.cs` 強制 `.gitignore`
- AES-GCM tag 驗證自動防 tamper（已測試）
- 環境變數命名 `HARDVAULT_*` prefix 防撞名

### Tests

- **61 tests 全綠**
  - 41 unit tests（encrypt 10、schema 11、codegen 7、parse_cs 11、其他 2）
  - 17 integration tests（build / keygen / verify (--decrypt) / rotate e2e）
  - 3 roundtrip tests（byte layout 與 C# Provider 預期一致，含 1000 次 nonce 唯一性）

---

## 版本管理約定

- **MAJOR**：不向後相容的 API / 加密格式變更
- **MINOR**：新增功能、新增 CLI 子命令、新增 C# API
- **PATCH**：bug 修復、文件更新、依賴升級

[Unreleased]: https://github.com/Jarry6304/hardvault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Jarry6304/hardvault/releases/tag/v0.1.0
