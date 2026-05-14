// HARDVAULT — C# 端 ISecretProvider 參考實作
//
// 註冊（Program.cs）：
//   builder.Services.AddSingleton<ISecretProvider, GeneratedSecretsProvider>();
//
// 一般取值（簡便，但 string 落入 GC，無法保證何時清除）：
//   var token = secrets.Get("LINE_TOKEN");
//
// 高敏感取值（推薦，IDisposable 包裝，Dispose 自動 ZeroMemory）：
//   using var secret = secrets.GetSecret("DB_PASSWORD");
//   DoSomething(secret.AsSpan());
//
// 預期 codegen 產生的 partner class（由 hardvault build 寫出，**不**進 Git）：
//
//   namespace Hardvault.Security;
//
//   internal static class GeneratedSecrets
//   {
//       internal readonly record struct Entry(bool Encrypted, byte[] Data);
//
//       internal static readonly IReadOnlyDictionary<string, Entry> Entries =
//           new Dictionary<string, Entry>
//           {
//               ["LINE_TOKEN"]  = new(true,  new byte[] { 0x1a, 0x2b, /* ... */ }),
//               ["SCAN_CRON"]   = new(false, new byte[] { /* "0 0 8 * * *" UTF-8 */ }),
//           };
//   }

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Hardvault.Security;

public interface ISecretProvider
{
    string Get(string key);
    SecretValue GetSecret(string key);
    bool TryGet(string key, out string value);
}

/// <summary>
/// IDisposable 包裝的明文。Dispose 時自動 ZeroMemory，避免 string 進入 GC 不可控的生命週期。
/// </summary>
public sealed class SecretValue : IDisposable
{
    private byte[]? _data;

    internal SecretValue(byte[] data) => _data = data;

    public ReadOnlySpan<byte> AsSpan()
        => _data ?? throw new ObjectDisposedException(nameof(SecretValue));

    public string AsString()
    {
        if (_data is null) throw new ObjectDisposedException(nameof(SecretValue));
        return Encoding.UTF8.GetString(_data);
    }

    public void Dispose()
    {
        if (_data is null) return;
        CryptographicOperations.ZeroMemory(_data);
        _data = null;
    }
}

public sealed class GeneratedSecretsProvider : ISecretProvider, IDisposable
{
    private const int KeyLen = 32;        // AES-256
    private const int NonceLen = 12;
    private const int TagLen = 16;
    private const int OverheadLen = NonceLen + TagLen;

    private readonly byte[] _masterKey;
    private bool _disposed;

    public GeneratedSecretsProvider()
    {
        var b64 = Environment.GetEnvironmentVariable("HARDVAULT_MASTER_KEY")
            ?? throw new InvalidOperationException(
                "環境變數 HARDVAULT_MASTER_KEY 未設定。請執行 hardvault keygen 產生並設定。");

        byte[] key;
        try
        {
            key = Convert.FromBase64String(b64);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                "HARDVAULT_MASTER_KEY 不是合法的 base64 字串。", ex);
        }

        if (key.Length != KeyLen)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidOperationException(
                $"HARDVAULT_MASTER_KEY 必須為 {KeyLen} bytes (AES-256)，目前 {key.Length} bytes。");
        }

        _masterKey = key;
    }

    public string Get(string key)
    {
        EnsureNotDisposed();
        var entry = LookupOrThrow(key);

        if (!entry.Encrypted)
            return Encoding.UTF8.GetString(entry.Data);

        var ptLen = entry.Data.Length - OverheadLen;
        var pt = ArrayPool<byte>.Shared.Rent(ptLen);
        try
        {
            Decrypt(entry.Data, pt.AsSpan(0, ptLen));
            return Encoding.UTF8.GetString(pt, 0, ptLen);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pt.AsSpan(0, ptLen));
            ArrayPool<byte>.Shared.Return(pt);
        }
    }

    public SecretValue GetSecret(string key)
    {
        EnsureNotDisposed();
        var entry = LookupOrThrow(key);

        if (!entry.Encrypted)
        {
            var copy = new byte[entry.Data.Length];
            Buffer.BlockCopy(entry.Data, 0, copy, 0, copy.Length);
            return new SecretValue(copy);
        }

        var pt = new byte[entry.Data.Length - OverheadLen];
        Decrypt(entry.Data, pt);
        return new SecretValue(pt);
    }

    public bool TryGet(string key, out string value)
    {
        EnsureNotDisposed();
        if (!GeneratedSecrets.Entries.ContainsKey(key))
        {
            value = string.Empty;
            return false;
        }
        value = Get(key);
        return true;
    }

    private static GeneratedSecrets.Entry LookupOrThrow(string key)
    {
        if (!GeneratedSecrets.Entries.TryGetValue(key, out var entry))
            throw new KeyNotFoundException(
                $"Secret '{key}' 未在 secrets.toml 中定義。請新增後重新執行 hardvault build。");
        return entry;
    }

    // blob layout: [12-byte nonce][ciphertext][16-byte tag]
    private void Decrypt(byte[] blob, Span<byte> dest)
    {
        if (blob.Length < OverheadLen)
            throw new CryptographicException("密文長度異常（少於 28 bytes 的 nonce+tag 開銷）。");

        var ctLen = blob.Length - OverheadLen;
        if (dest.Length < ctLen)
            throw new ArgumentException("目的緩衝區太小。", nameof(dest));

        var nonce = blob.AsSpan(0, NonceLen);
        var ct    = blob.AsSpan(NonceLen, ctLen);
        var tag   = blob.AsSpan(blob.Length - TagLen, TagLen);

        using var aes = new AesGcm(_masterKey, TagLen);
        aes.Decrypt(nonce, ct, tag, dest[..ctLen]);
    }

    private void EnsureNotDisposed()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(GeneratedSecretsProvider));
    }

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_masterKey);
        _disposed = true;
    }
}
