# Contributing to HARDVAULT

謝謝你想要貢獻 ⭐

完整指南見 [README#貢獻指南](README.md#貢獻指南)。本檔是 GitHub UI 自動偵測的快速入口，
開 Issue / PR 時會被連結。

---

## 快速 Checklist

提 PR 前確認：

- [ ] `cargo fmt --all` 過
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 過
- [ ] `cargo test` 全綠
- [ ] 若改了 C# sample，本機 `dotnet build sample/Hardvault.Sample` 過
- [ ] Commit message 遵循 [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] PR 描述含 `## Test plan` 區段
- [ ] 若改加密格式或 byte layout，請更新 `docs/ARCHITECTURE.md` 與相關測試

## Branch 命名

- `feat/XXX`：新功能
- `fix/XXX`：bug 修復
- `docs/XXX`：純文件
- `refactor/XXX`：行為不變的重構
- `chore/XXX`：依賴、設定、其他維護

## Commit prefix

對應 Conventional Commits：

| Prefix | 用途 |
|---|---|
| `feat:` | 新功能 |
| `fix:` | bug 修復 |
| `docs:` | 文件 |
| `refactor:` | 重構 |
| `test:` | 加測試 |
| `chore:` | 維護 |
| `ci:` | CI/CD 設定 |
| `chore(deps):` | 依賴升級（dependabot 自動產） |

## 程式碼風格

- **Rust**：`cargo fmt` + `cargo clippy`，不抗拒任何 lint
- **C#**：[.NET 官方規範](https://learn.microsoft.com/dotnet/csharp/fundamentals/coding-style/coding-conventions)
- **XML / csproj**：XML 註解內**不可有 `--`**（spec 規定）

## 測試要求

新功能必須帶測試。修 bug 至少加一個 regression test。

| 層級 | 位置 | 適用 |
|---|---|---|
| Unit | `hardvault/src/<module>.rs` 內 `#[cfg(test)] mod tests` | 模組內部邏輯 |
| Integration | `hardvault/tests/integration.rs` | 呼叫 binary 驗證 e2e |
| Roundtrip | `hardvault/tests/roundtrip.rs` | byte layout 與 C# 端必須一致 |

## 動到加密格式時的特殊規則

如果 PR 修改了：
- `src/encrypt.rs` 的 byte layout
- `src/codegen.rs` 的 C# 產出格式
- `reference/GeneratedSecretsProvider.cs` 的 Decrypt 邏輯

必須**同時**：
1. 更新對應的 roundtrip 測試
2. 升 Cargo.toml 版本號（這算 breaking）
3. 在 `CHANGELOG.md` 的 `[Unreleased]` 加 `### Changed` 條目，標 BREAKING

---

## 回報安全問題

**請勿開 Public Issue。** 直接寄信至維護者信箱（見 GitHub Profile），
主旨開頭加 `[SECURITY]`，內容含：

- 問題類型（密碼學？實作？文件？）
- 重現步驟
- 影響範圍

詳見 [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) 的「安全回報」段。

---

## 行為準則

本專案遵循 [Contributor Covenant](https://www.contributor-covenant.org/)。
請以尊重、建設性的態度互動。
