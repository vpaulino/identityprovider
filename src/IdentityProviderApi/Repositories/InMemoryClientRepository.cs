using System.Collections.Generic;

public record OAuthClient(string ClientId, string Name, string RedirectUri, string[] AllowedScopes);

public interface IClientRepository
{
    void Add(OAuthClient client);
    OAuthClient? Get(string clientId);
    IEnumerable<OAuthClient> GetAll();
}

public class InMemoryClientRepository : IClientRepository
{
    private readonly Dictionary<string, OAuthClient> _clients = new();

    public void Add(OAuthClient client)
    {
        _clients[client.ClientId] = client;
    }

    public OAuthClient? Get(string clientId)
    {
        return _clients.TryGetValue(clientId, out var client) ? client : null;
    }

    public IEnumerable<OAuthClient> GetAll() => _clients.Values;
}