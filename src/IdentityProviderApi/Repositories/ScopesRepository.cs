using System;
using System.Collections.Generic;

namespace IdentityProviderApi.Repositories
{
    public record ScopeDefinition(string Name, string Audience, string? Description = null);


    public interface IScopeRepository
    {
        void Add(ScopeDefinition scope);
        ScopeDefinition? Get(string name);
        IEnumerable<ScopeDefinition> GetAll();
    }

    public class InMemoryScopeRepository : IScopeRepository
    {
        private readonly Dictionary<string, ScopeDefinition> _scopes = new(StringComparer.OrdinalIgnoreCase);

        public void Add(ScopeDefinition scope)
        {
            _scopes[scope.Name] = scope;
        }

        public ScopeDefinition? Get(string name)
        {
            _scopes.TryGetValue(name, out var scope);
            return scope;
        }

        public IEnumerable<ScopeDefinition> GetAll() => _scopes.Values;
    }


}
