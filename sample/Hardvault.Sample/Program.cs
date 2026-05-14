using Hardvault.Sample.Services;
using Hardvault.Security;

Console.WriteLine("=== HARDVAULT Sample ===");
Console.WriteLine();

using var provider = new GeneratedSecretsProvider();

Console.WriteLine("明文設定（直接燒入 exe）：");
Console.WriteLine($"  SCAN_CRON  = {provider.Get("SCAN_CRON")}");
Console.WriteLine($"  PAGE_SIZE  = {provider.Get("PAGE_SIZE")}");

Console.WriteLine();
Console.WriteLine("加密設定（AES-256-GCM 解密）：");
using (var token = provider.GetSecret("LINE_TOKEN"))
{
    var s = token.AsString();
    var preview = s.Length > 8 ? s[..8] + "***" : s;
    Console.WriteLine($"  LINE_TOKEN = {preview} (length={s.Length})");
}

Console.WriteLine();
Console.WriteLine("模擬使用：");
var notifier = new NotificationService(provider);
notifier.Send("Hello from HARDVAULT");

Console.WriteLine();
Console.WriteLine("=== 驗證雙層防線 ===");
Console.WriteLine("  試試：unset HARDVAULT_MASTER_KEY && dotnet run");
Console.WriteLine("  預期：InvalidOperationException — 環境變數未設定");
