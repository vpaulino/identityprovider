using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

public record AuthCodeInfo(
    string Code,
    string ClientId,
    string RedirectUri,
    List<string> Scopes,
    string Subject,
    DateTime ExpiresAt,
    string? Nonce,
    string? State,
    string? Prompt,
    string? LoginHint,
    int? MaxAge,
    string Audience
);


public interface IAuthCodeRepository
{
    void Store(AuthCodeInfo info);
    AuthCodeInfo? Get(string code);
    void Remove(string code);
}

public class InMemoryAuthCodeRepository : IAuthCodeRepository
{
    private readonly ConcurrentDictionary<string, AuthCodeInfo> _store = new();

    public void Store(AuthCodeInfo info)
    {
        _store[info.Code] = info;
    }

    public AuthCodeInfo? Get(string code)
    {
        _store.TryGetValue(code, out var info);
        return info;
    }

    public void Remove(string code)
    {
        _store.TryRemove(code, out _);
    }
}