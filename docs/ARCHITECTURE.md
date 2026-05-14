# HARDVAULT 架構

本文件解釋 HARDVAULT 的設計決策與背後的取捨。閱讀順序建議：
[README](../README.md) → 本文件 → [THREAT-MODEL](THREAT-MODEL.md)。

---

## 設計目標

1. **零外部服務** — 個人專案 / 小型團隊用，不依賴 Azure / AWS / HashiCorp Vault
2. **零持續成本** — 完全免費，無 KMS 月費
3. **跨機器搬遷** — 部署到新主機只需設定一個環境變數
4. **提高逆向門檻** — 即使 exe 落入攻擊者手裡，沒有金鑰仍不可解
5. **錯誤難以隱形** — 開發階段就能看到設定錯誤（缺 key、TOML 格式錯）

明確**不**追求：
- 動態更新（設定變更必須重新部署）
- 審計日誌 / 版本歷史 / 細粒度權限
- 防護 Production 主機被完全攻破（這時 KMS 也救不了）

---

## 為什麼是「雙層防線」？

所有「把機敏值放在某處」的方案最終都要回答：金鑰本身要放哪？

| 方案 | 金鑰位置 | 弱點 |
|---|---|---|
| 純加密檔案 | 同檔案旁邊 / 程式碼裡 | 一拿就破 |
| DPAPI / Keychain | OS 管理 | 換機器 / 容器化困難 |
| KMS | 雲端服務 | 預算、複雜度、雲商鎖定 |
| **HARDVAULT** | **環境變數（與密文物理隔離）** | 兩邊都被偷才會破 |

「物理隔離」意思是：
- **密文** 燒在編譯後的 exe 內（檔案系統中的一份成品）
- **金鑰** 在執行環境的記憶體 / OS env 表內（另一份成品）

要還原明文必須**同時**取得兩邊。攻擊者通常只能拿到一邊：
- 拿到 GitHub repo → 只有 KEY 清單（appsettings.json），沒有 VALUE
- 拿到部署主機 exe → 有密文，但沒有金鑰
- 拿到金鑰 → 沒有密文，無物可解

這不是無敵 — 當攻擊者完全控制部署主機時，env + exe 都會被一起拿走。但對「離線分析」、「公開倉庫掃描」、「備份外洩」這些常見場景，雙層防線可有效擋下。

---

## 為什麼用 Rust 寫 codegen？

C# 應該也能寫 codegen。為什麼選 Rust？

### 1. Native binary 比 .NET IL 難逆向

.NET 程式編譯成 IL（Intermediate Language），保留近乎完整的型別、方法名、字串常量。用 `ILSpy` / `dnSpy` 反組譯可以直接讀回近似原始碼。

Rust 編譯成 native 機器碼，搭配 `strip + LTO + panic=abort` 後：
- 符號表移除（看不到函式名）
- 字串常量還在，但分散在 binary 各處，難以對應
- 沒有 panic backtrace 的字串提示
- LTO 跨 crate 內聯後，函式邊界模糊

並非「不可逆向」，只是門檻顯著更高。對個人專案規模的攻擊者來說足夠。

### 2. 記憶體安全

加密程式碼路徑上的 buffer overflow / use-after-free 是真實風險。Rust 的 ownership system 在編譯期消除這類問題。

對比：C# 也是 managed，但呼叫 `AesGcm` 時仍會經過 unsafe interop；自己寫 codegen 又會多一個風險面。

### 3. `zeroize` crate 比 .NET 對應方案乾淨

Rust 的 `zeroize::Zeroizing<T>` 是 RAII 包裝，離開作用域自動清除：

```rust
let mut key = Zeroizing::new([0u8; 32]);
rand::thread_rng().fill_bytes(&mut *key);
// 用完不需手動 zero，drop 時自動處理
```

C# 的對應 (`CryptographicOperations.ZeroMemory`) 必須手動呼叫，且 string 是 immutable 無法 zero（這也是 Provider 設計 `SecretValue: IDisposable` 的原因 — 詳見下節）。

---

## 加密格式

每筆密文的 byte layout：

```
┌────────────┬──────────────────┬────────────┐
│  nonce 12  │  ciphertext N    │   tag 16   │
└────────────┴──────────────────┴────────────┘
   0..12         12..N+12         N+12..N+28
```

### 為什麼選 AES-256-GCM

| 演算法 | 選或不選 | 理由 |
|---|---|---|
| AES-256-GCM | ✅ | NIST 認證、有認證標籤（tag）防 tamper、Rust/C# 兩邊都有原生支援 |
| ChaCha20-Poly1305 | ❌ | 同樣優秀，但 AES-GCM 有 AES-NI 硬體加速；.NET 預設無 ChaCha20 |
| AES-256-CBC + HMAC | ❌ | 需要兩個 key 或 KDF，且 padding oracle 攻擊風險 |
| AES-256-GCM-SIV | ❌ | 抗 nonce 重用但較少實作；本工具 nonce 每次隨機，不需要 SIV |

### nonce 策略

每次加密**重新產生** nonce（從 OS RNG）。GCM 安全性建立在「同一 key 下 nonce 不重用」。32 bytes 隨機 nonce 衝突機率為 2^-96（生日攻擊下安全使用 2^32 次加密）。

替代方案 deterministic nonce（如 `SHA256(key || plaintext)[..12]`）會讓相同明文產生相同密文，方便 diff 但洩漏「兩個 KEY 是否相同值」這個 metadata。我們不選此路。

### tag 長度

固定 16 bytes（128-bit），AES-GCM 預設且最強。短於此會降低 forgery 抗性。

---

## 為什麼 BTreeMap 而非 HashMap？

Rust 端 `SecretsToml` 與 `codegen::build_cs` 內部都用 `BTreeMap<String, _>`：

```rust
pub struct SecretsToml {
    pub secrets: BTreeMap<String, String>,
    pub config:  BTreeMap<String, String>,
}
```

理由：**確保 KEY 順序穩定**。同樣 `secrets.toml` 多次 build 應產生**結構相同**的 `GeneratedSecrets.cs`（只有 nonce + ciphertext 因隨機性而不同）。

如果用 HashMap，HashMap 迭代順序在 Rust 中是隨機化的，每次 build 出的 .cs 連 KEY 順序都會變，diff 起來雜訊很大。

---

## C# 端的 `SecretValue: IDisposable`

問題：.NET 的 `string` 是 immutable，且由 GC 管理，無法主動 `ZeroMemory`。一旦明文進入 string，何時被清除完全不可控。

解法：提供兩條 API。

```csharp
// 一般情況（API token、URL、設定值）
var token = provider.Get("LINE_TOKEN");      // 回 string，便利但無法 zero

// 高敏感情況（DB 密碼、私鑰、PII）
using var secret = provider.GetSecret("DB_PASSWORD");
DoSomething(secret.AsSpan());                // ReadOnlySpan<byte>
// 離開 using → Dispose → CryptographicOperations.ZeroMemory(byte[])
```

`SecretValue` 內部持有 `byte[]`，Dispose 時清除。`AsString()` 仍會把 string 帶進 GC，但只在你**明確**選擇時才會發生。

### 已知限制

- string 一旦產生就無法清除
- `Encoding.UTF8.GetString(...)` 過程中可能短暫複製到內部 buffer
- 若 OS 把記憶體分頁 swap 到磁碟，明文可能殘留

對個人專案規模這是可接受的。對極度敏感場景（核機資料）請走 KMS + HSM。

---

## MSBuild 整合策略

`Hardvault.Sample.csproj` 內的 `<Target>` 流程：

```xml
<!-- 1. 從預設 glob 排除 GeneratedSecrets.cs（檔案還沒產生） -->
<ItemGroup>
  <Compile Remove="Infrastructure/Security/GeneratedSecrets.cs" />
</ItemGroup>

<!-- 2. CoreCompile 之前：環境檢查 + 執行 hardvault + 動態加入 @(Compile) -->
<Target Name="HardvaultBuild" BeforeTargets="CoreCompile">
  <Error Condition="'$(HARDVAULT_MASTER_KEY)' == ''" Text="..." />
  <Exec Command="..." />
  <Error Condition="!Exists('$(HardvaultOutCs)')" Text="..." />
  <ItemGroup>
    <Compile Include="$(HardvaultOutCs)" />
  </ItemGroup>
</Target>
```

### 為什麼這個順序？

.NET SDK-style 專案的 `**\*.cs` glob 在**專案載入時**評估，早於任何 Target 執行。所以「Target 內產生的檔案」不會自動進 `@(Compile)`。

兩個常見錯誤解法：
1. ❌ 把產生的檔案放在預設 glob 範圍外 — 仍然要手動 Include
2. ❌ 第一次 build 失敗、第二次成功 — UX 太差

正確解法：
1. 預設 glob **排除** 那個檔案路徑（即使檔案不存在也沒事）
2. Target 執行完後**動態** `<Compile Include>` 把它加進去

這樣首次 build 就成功，避免 "double build" 困境。

### 為什麼不傳 `--master-key` flag？

CLI 旗標會出現在：
- shell history（`.bash_history`、PowerShell history）
- 父 process 的 `argv`（`ps aux`、Task Manager 可見）
- CI log（GitHub Actions logs）
- crash dump

把金鑰寫進 csproj 的 `<Exec Command>` 也會有同樣問題。所以 HARDVAULT 的硬性規則是 **CLI 永遠不接受 --master-key 旗標**，金鑰只從 env var 讀。

---

## 為什麼 lib + bin 而非單 bin？

`hardvault/Cargo.toml` 同時定義 `[lib]` 與 `[[bin]]`：

```toml
[lib]
name = "hardvault"
path = "src/lib.rs"

[[bin]]
name = "hardvault"
path = "src/main.rs"
```

- `[lib]` 讓整合測試（`tests/roundtrip.rs`）可以 `use hardvault::encrypt::*`，直接驗證加密邏輯
- `[[bin]]` 讓 `cargo install` 產生可執行的 CLI
- main.rs 內部用 `use hardvault::...` 從 lib 引用，不重複實作

代價：build 時間略多（lib 與 bin 兩次 codegen），但對小型 crate 可忽略。

---

## Release profile

```toml
[profile.release]
opt-level     = 3       # 最高最佳化
lto           = "fat"   # 跨 crate LTO，最大化內聯與 dead code elimination
codegen-units = 1       # 單一 codegen unit，犧牲編譯速度換 runtime 速度
panic         = "abort" # panic 不展開 stack，移除展開機制
strip         = "symbols" # 移除符號表
```

效果：
- Binary 大小通常 < 3 MB
- 符號表（函式名）幾乎清空
- Panic 字串（如 `unwrap on None`）被 abort 機制簡化
- LTO 後函式邊界模糊，反組譯困難

---

## 為什麼 KEY 命名要嚴格？

`secrets.toml` 的 KEY 必須符合 `^[A-Z][A-Z0-9_]*$`：

```toml
[secrets]
LINE_TOKEN  = "ok"          # ✅
db_password = "fail"        # ❌ 小寫
"API-KEY"   = "fail"        # ❌ 連字號
1ST_KEY     = "fail"        # ❌ 數字開頭
```

理由：
1. **C# 字典 key** — `Entries["KEY_NAME"]`，命名一致才好讀
2. **環境變數慣例** — 多數系統的 env var 都是 SCREAMING_SNAKE_CASE
3. **避免 codegen 嘴砲** — 嚴格規則減少 edge case，codegen 不用處理特殊字元 escape

`is_valid_key_name` 不引 `regex` crate，純 `chars().all()` 實作，省幾百 KB binary 大小。

---

## 取捨總結

| 決策 | 我們選 | 代價 |
|---|---|---|
| 加密演算法 | AES-256-GCM | 無 |
| nonce 策略 | 每次隨機 | build 不可重現（KEY 順序穩定但 nonce / ciphertext 變） |
| 金鑰來源 | 環境變數 | 不接受 CLI 旗標 |
| codegen 語言 | Rust | 多一個 toolchain 依賴 |
| C# 取值 API | string + SecretValue | API 二元，使用者要選對 |
| BTreeMap | Yes | HashMap 略快但順序不穩 |
| KEY 命名 | 嚴格 SCREAMING_SNAKE_CASE | 不支援 PascalCase 等命名 |
| build pipeline | MSBuild Target | 只在 .NET 環境可用 |

---

## 未來規劃

詳見 [README 路線圖](../README.md#路線圖-roadmap)。簡略：

- `hardvault rotate` — 換 key 重編密文
- `hardvault verify --decrypt` — 不只比對 KEY 清單，還驗證密文能解
- HashiCorp Vault 整合 — 把 `HARDVAULT_MASTER_KEY` 改從 Vault 讀
- NuGet 套件 — 把 Provider + interface 打包，使用者不用 copy reference 檔案

---

## 延伸閱讀

- [THREAT-MODEL.md](THREAT-MODEL.md) — 完整威脅模型
- [reference/hardvault_cli_notes.md](../reference/hardvault_cli_notes.md) — CLI 設計筆記
- [SKILL.md](../SKILL.md) — 給 AI agent 的精簡規格
