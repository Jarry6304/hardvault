# HARDVAULT 威脅模型

本文件用 STRIDE 方法系統化盤點 HARDVAULT 的攻擊面與防禦邊界，
讓讀者明確知道：**這個工具擋什麼、不擋什麼**。

> ⚠ 本文件是給「打算採用 HARDVAULT」的人讀的。
> 如果你需要的是「企業合規等級」的威脅評估，請尋求專業安全顧問。

---

## 資產（Assets）

我們要保護的是什麼？

| 資產 | 形式 | 重要性 |
|---|---|---|
| **明文機敏值** | API token、DB 密碼等 | ⭐⭐⭐ 主要保護目標 |
| `HARDVAULT_MASTER_KEY` | 32 bytes base64 | ⭐⭐⭐ 解密金鑰 |
| `secrets.toml` | 開發機上的明文檔案 | ⭐⭐ 是所有機敏值的源頭 |
| `GeneratedSecrets.cs` | 編譯前的中間產物 | ⭐ 含密文，但無 key 無用 |
| 編譯後 exe | 部署成品 | ⭐ 同上，含密文 |

---

## 攻擊者模型（Attackers）

| 攻擊者 | 能力 | 動機 |
|---|---|---|
| **A1：公開倉庫掃描者** | 讀公開 GitHub repo | 大規模掃描，找 hardcoded secrets |
| **A2：私倉外洩** | 私倉的歷史 commit、PR diff | 同 A1 的針對性版本 |
| **A3：靜態 exe 分析** | 取得部署後 exe 檔案，離線分析 | 逆向工程，找密文與 key 關係 |
| **A4：部署環境讀取** | RCE / SSH 進入 production，但不持久化 | 拿 env vars 或記憶體 dump |
| **A5：開發機入侵** | 拿到開發者本機檔案存取 | 拿 `secrets.toml` 或開發環境 env |
| **A6：CI/CD 妥協** | 修改 build pipeline、讀 CI secrets | 注入後門、拿 production key |
| **A7：供應鏈攻擊** | 控制 hardvault crate、aes-gcm 等依賴 | 後門加密過程 |

---

## STRIDE 分析

### S — Spoofing（身分偽造）

**威脅：** 攻擊者偽裝成授權使用者讀取 secrets。

**HARDVAULT 預設範圍：** 不在保護範圍。我們假設「能執行 exe 的人」就是授權使用者。

**現實對應：** 如果 production 主機被入侵到能執行 exe + 讀環境變數，攻擊者已**等於**授權使用者。HARDVAULT 不能解決此層威脅 — 那是 OS / 雲端 IAM 的職責。

---

### T — Tampering（資料竄改）

**威脅：** 攻擊者修改密文，希望解密後得到對自己有利的明文。

**HARDVAULT 的防禦：** **AES-256-GCM 內建認證標籤**。任何 byte 被改動（包括 nonce、ciphertext、tag）都會在解密時 tag 驗證失敗，拋 `CryptographicException`。

**測試覆蓋：** `encrypt::tests::tampered_blob_fails`、`tampered_nonce_fails`、`truncated_blob_fails`。

**剩餘風險：** 攻擊者可以**刪除**整筆 entry。應用層應檢查必要 KEY 存在（`provider.Get("KEY")` 找不到時拋 `KeyNotFoundException`）。

---

### R — Repudiation（否認）

**威脅：** 使用者否認曾經操作。

**HARDVAULT 預設範圍：** 不在保護範圍。我們不記錄誰執行 hardvault build、不記錄 secret 使用日誌。

**現實對應：** 個人 / 小團隊不需審計。需要審計請走 KMS（Azure Key Vault、AWS Secrets Manager 都有 access log）。

---

### I — Information Disclosure（資訊洩漏）

**這是本工具的主戰場。** 詳見下方「攻擊面矩陣」。

---

### D — Denial of Service（阻斷服務）

**威脅：** 攻擊者讓 secrets 無法使用。

**HARDVAULT 預設範圍：** 不在保護範圍。Secret storage 通常不關心 DoS（攻擊者就算拿掉 secret，也只是讓你的服務掛掉，不會更糟）。

---

### E — Elevation of Privilege（權限提升）

**威脅：** 一般使用者取得管理者權限。

**HARDVAULT 預設範圍：** 不在保護範圍。HARDVAULT 是一個無權限分層的工具 — 任何能執行 exe 的人都能讀所有 secrets。

**設計建議：** 應用層自己做權限分隔（例如：admin API 才呼叫 `provider.Get("ADMIN_TOKEN")`，普通 endpoint 不取）。

---

## 攻擊面矩陣（Information Disclosure 主戰場）

對每個攻擊者，列出「能拿到什麼」與「能還原明文嗎」。

| 攻擊者 | 能拿到 | 還原明文？ | 為什麼 |
|---|---|---|---|
| **A1：公開倉庫掃描** | `appsettings.json`、`README.md` | ❌ | appsettings 只有 KEY 清單，無 VALUE |
| **A2：私倉外洩** | 同上 + 歷史 commit | ❌ | 同上（前提：`secrets.toml`、`GeneratedSecrets.cs` 在 `.gitignore`） |
| **A3：靜態 exe 分析** | 密文（嵌在 binary 中） | ❌ | AES-256-GCM 無金鑰不可解 |
| **A4：部署環境讀取** | 密文 + env var | ✅ | 雙層都被拿，必然破解 |
| **A5：開發機入侵** | `secrets.toml` 明文 | ✅ | 直接讀 |
| **A6：CI/CD 妥協** | CI 設定的 env var、build artifact | ✅ | 同 A4 |
| **A7：供應鏈攻擊** | 加密過程被植入後門 | ✅ | aes-gcm crate / hardvault crate 被改 |

### 重點觀察

1. **A1 / A2 / A3**（最常見的「離線」威脅）—— **HARDVAULT 完全防護**
2. **A4 / A6**（執行環境被攻陷）—— HARDVAULT 不能防，但任何加密方案都不能防
3. **A5**（開發機入侵）—— `secrets.toml` 是最大弱點
4. **A7**（供應鏈）—— 通用威脅，所有 Rust/C# 工具都有此風險

---

## 各攻擊面的對應防禦

### A1 / A2 — Git 倉庫外洩

**HARDVAULT 自帶防護：**
- `appsettings.json` 只有 KEY 清單
- `secrets.toml`、`GeneratedSecrets.cs` 強制 `.gitignore`

**使用者責任：**
- 不要把 `HARDVAULT_MASTER_KEY` 寫進 commit message、PR description
- Pre-commit hook 偵測敏感字串（grep `HARDVAULT_MASTER_KEY=`）
- 如已 commit：BFG Repo-Cleaner / `git filter-repo` 清歷史 + 立即輪替 key

---

### A3 — 靜態 exe 分析

**HARDVAULT 自帶防護：**
- Rust 編譯成 native binary，無 IL metadata
- `strip + LTO + panic=abort` 移除符號表
- 密文以 byte array 字面量散布在 binary 各處
- AES-256-GCM 無 key 不可解（256-bit 暴力搜尋不可行）

**剩餘風險：**
- 攻擊者可看到密文長度（推斷出明文大致長度）
- 攻擊者可看到 KEY 清單（從 `appsettings.json` 或 exe 內字面量）
- 進階攻擊者可從 byte 模式辨識「這是 AES-GCM 密文」

**使用者責任：** 無特別需求。HARDVAULT 預設配置即足夠。

---

### A4 — 部署環境讀取

**HARDVAULT 不能防護。** 當攻擊者進入 production：
- exe 在檔案系統內
- `HARDVAULT_MASTER_KEY` 在 env 表內
- 兩個都能讀 → 雙層防線崩潰

**使用者責任：**
- Production 主機開啟全盤加密（at-rest encryption）
- Cloud workload 設定最小權限 IAM（最小 trust boundary）
- 監控 process / env 異常存取
- **若懷疑被入侵：立即輪替 `HARDVAULT_MASTER_KEY` + 重新部署**

---

### A5 — 開發機入侵

**HARDVAULT 不能防護。** `secrets.toml` 明文存在開發機上是必要的（這是「真實來源」）。

**使用者責任：**
- 開發機開啟全盤加密（BitLocker / FileVault / LUKS）
- `secrets.toml` 不放雲端同步資料夾（Dropbox、OneDrive、iCloud）
- 用 1Password / Bitwarden 等密碼管理器存「最權威」副本，工作機只是工作複本
- 螢幕鎖 + 自動鎖屏
- 開發機 SSH key 用硬體 key（YubiKey）保護

---

### A6 — CI/CD 妥協

**HARDVAULT 不能防護。** CI 上必須有 `HARDVAULT_MASTER_KEY` 才能 build（或 build 在開發機，CI 不需要）。

**使用者責任：**
- 限制 CI secret 的存取角色（最小權限）
- CI provider 開啟 2FA
- 監控 CI log 是否意外印出 secrets（grep `HARDVAULT_MASTER_KEY=`）
- 不在 fork PR 上跑使用 secrets 的 workflow（GitHub Actions 預設安全）

---

### A7 — 供應鏈攻擊

**HARDVAULT 不能完全防護，但有降低面：**
- 依賴清單最小化（aes-gcm、clap、serde、toml、base64、rand、anyhow、thiserror、zeroize）
- 都是 well-known crates，社群審計多
- `Cargo.lock` commit 進 repo，鎖死版本

**使用者責任：**
- 定期 `cargo audit` 檢查已知 CVE
- 升級依賴前看 changelog
- 不隨便 `cargo update --aggressive`

---

## 殘留風險（Residual Risks）

即使所有建議都遵守，仍有：

1. **OS swap 殘留** — 解密後的明文若分頁到 swap，重啟前可能殘留
   - 緩解：production 用 `mlockall` 或關閉 swap
2. **記憶體 dump** — debugger 或 core dump 可能含明文
   - 緩解：production 關閉 core dump、限制 ptrace 權限
3. **side-channel** — AES 在某些 CPU 上有 timing attack 風險
   - 緩解：aes-gcm crate 用 constant-time 實作，已預防
4. **Provider 拿到 string 後** — string immutable，何時 GC 不可控
   - 緩解：對極敏感資料用 `SecretValue` API
5. **量子計算** — 未來大型量子電腦可能能破 AES-256（Grover 算法，等效 128-bit 安全）
   - 緩解：目前 (2026) 不在威脅範圍

---

## 不在保護範圍的明確聲明

**HARDVAULT 不防護：**
- ❌ Production 主機被 root 後的資料外洩
- ❌ 開發者帳號被入侵
- ❌ 雲端 IAM 設定錯誤導致的全面失守
- ❌ 社交工程（攻擊者騙到金鑰）
- ❌ 物理盜竊解鎖中的開發機
- ❌ 內部威脅（離職員工帶走 `secrets.toml`）
- ❌ 量子電腦未來威脅
- ❌ 嚴重密碼學突破（AES-GCM 被找到實際弱點）

**這些是真實但更高層次的威脅。** 適合的應對手段：
- KMS / HSM（取代 HARDVAULT）
- Endpoint detection（防 A5）
- Cloud IAM 設計（防 A4）
- 員工管理流程（防內部）

HARDVAULT **只是工具鏈中的一環**，不是銀彈。

---

## 對標其他方案

| 方案 | 防 A1/A2/A3 | 防 A4 | 防 A5 | 防 A6 |
|---|---|---|---|---|
| `appsettings.json` 裸 | ❌ | ❌ | ❌ | ❌ |
| 環境變數 | ⚠️（容易誤 commit） | ❌ | ❌ | ❌ |
| DPAPI | ✅ | ❌ | 部分 | N/A |
| **HARDVAULT** | ✅ | ❌ | ❌ | ❌ |
| Azure Key Vault | ✅ | 部分（access log） | ✅ | 部分 |
| HSM | ✅ | 部分 | ✅ | ✅ |

對 A1/A2/A3（最常見）HARDVAULT 與 Key Vault 同級。對 A4/A5/A6（執行環境威脅）Key Vault 領先（access log + IAM）。

**結論：** 個人 / 小型專案的常見威脅在 A1/A2/A3，HARDVAULT 足夠。需要 A4-A6 防護請升級到 Key Vault。

---

## 安全回報

發現 HARDVAULT 本身有安全問題（演算法錯誤、實作 bug、文件誤導），請**勿開 Public Issue**。

直接寄信至維護者信箱（見 GitHub Profile），主旨開頭加 `[SECURITY]`，內容包括：
- 問題類型（密碼學？實作？文件？）
- 重現步驟
- 影響範圍
- 建議修正方向

我們會在 30 天內回應。修正後會發 CVE（如適用）並在 release notes 致謝回報者。
