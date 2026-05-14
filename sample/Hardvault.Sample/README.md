# Hardvault.Sample

最小可跑範例：Console App 透過 HARDVAULT 從加密的 `GeneratedSecrets.cs` 讀取設定。

## 前置

### 1. 安裝 hardvault CLI

```bash
cd ../../hardvault
cargo install --path .
# 確認：hardvault --version
```

### 2. 產生並設定 master key

```bash
# Linux / macOS
export HARDVAULT_MASTER_KEY=$(hardvault keygen | head -1)

# Windows (PowerShell)
$env:HARDVAULT_MASTER_KEY = (hardvault keygen | Select-Object -First 1)

# Windows (CMD)
hardvault keygen > %TEMP%\hv.key
set /p HARDVAULT_MASTER_KEY=<%TEMP%\hv.key
```

### 3. 建立 secrets.toml

```bash
cp secrets.toml.example secrets.toml
# 編輯 secrets.toml 填入實際值
```

## 執行

```bash
dotnet run
```

預期輸出：

```
[hardvault build] ✓ Infrastructure/Security/GeneratedSecrets.cs
[hardvault build] ✓ appsettings.json
[hardvault build]   2 secret(s), 2 config(s)

=== HARDVAULT Sample ===

明文設定（直接燒入 exe）：
  SCAN_CRON  = 0 0 8 * * *
  PAGE_SIZE  = 50

加密設定（AES-256-GCM 解密）：
  LINE_TOKEN = ey_demo_*** (length=24)

模擬使用：
  [NotificationService] sending 'Hello from HARDVAULT' with token len=24
  [NotificationService] (demo — no real HTTP call made)

=== 驗證雙層防線 ===
  試試：unset HARDVAULT_MASTER_KEY && dotnet run
  預期：InvalidOperationException — 環境變數未設定
```

## 驗證雙層防線

### 移除環境變數

```bash
unset HARDVAULT_MASTER_KEY
dotnet run
```

預期：`InvalidOperationException: 環境變數 HARDVAULT_MASTER_KEY 未設定`

### 用錯誤的 key 解（同樣長度但內容不對）

```bash
# 重新產生一個 key 但不重新 build sample（保留舊密文 + 新 key）
export HARDVAULT_MASTER_KEY=$(hardvault keygen | head -1)
dotnet run --no-build       # 重要：不要 rebuild，否則密文會用新 key 重新加密
```

預期：`CryptographicException`（AES-GCM tag 驗證失敗）

## 檔案結構

```
Hardvault.Sample/
├── Hardvault.Sample.csproj          # MSBuild + hardvault build target
├── Program.cs                       # Console entry
├── Services/
│   └── NotificationService.cs       # 示範使用 SecretValue
├── secrets.toml.example             # ← 進 Git
├── secrets.toml                     # ← gitignored，你自己建
├── appsettings.json                 # ← hardvault build 產生，可進 Git（只有 KEY）
└── Infrastructure/Security/
    ├── GeneratedSecretsProvider.cs  # 連結到 reference/，單一真實來源
    └── GeneratedSecrets.cs          # ← hardvault build 產生，gitignored
```

## IDE 注意事項

第一次 clone 後在 IDE 開啟，會看到 `GeneratedSecrets` not found 的紅字。
**這是預期的**——該檔案由 `hardvault build` 生成。先在命令列跑一次 `dotnet build`
（會觸發 hardvault build target），檔案產生後 IDE 重新載入就會綠掉。
