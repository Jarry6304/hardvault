using Hardvault.Security;

namespace Hardvault.Sample.Services;

public sealed class NotificationService
{
    private readonly ISecretProvider _secrets;

    public NotificationService(ISecretProvider secrets) => _secrets = secrets;

    public void Send(string message)
    {
        // 真實實作會用 HttpClient + LINE Notify / Slack / Discord webhook 等
        // 這裡只示範 token 的取得與生命週期管理
        using var token = _secrets.GetSecret("LINE_TOKEN");
        Console.WriteLine($"  [NotificationService] sending '{message}' with token len={token.AsSpan().Length}");
        Console.WriteLine($"  [NotificationService] (demo — no real HTTP call made)");
        // 離開 using → SecretValue.Dispose() → CryptographicOperations.ZeroMemory
    }
}
