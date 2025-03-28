using IdentityProviderApi.Repositories;
using System.Collections.Generic;
using System.Linq;

namespace IdentityProviderApi.Scopes
{
    public interface IScopeValidator 
    {
        public bool ValidateScopes(string clientId, List<string> scopes, out List<string> invalid);


        // 🔁 Add this for OBO audience validation
        public bool ValidateAudience(string clientId, string audience, out List<string> invalidScopes);
    }
    public class ScopeValidator : IScopeValidator
    {
        private readonly IClientRepository _clientRepo;
        private readonly IScopeRepository _scopeRepo;

        public ScopeValidator(IClientRepository clientRepo, IScopeRepository scopeRepo)
        {
            _clientRepo = clientRepo;
            _scopeRepo = scopeRepo;
        }

        public bool ValidateScopes(string clientId, List<string> scopes, out List<string> invalid)
        {
            invalid = new();
            var client = _clientRepo.Get(clientId);
            if (client is null) return false;

            invalid = scopes.Where(s => !client.AllowedScopes.Contains(s)).ToList();
            return invalid.Count == 0;
        }

        // 🔁 Add this for OBO audience validation
        public bool ValidateAudience(string clientId, string audience, out List<string> invalidScopes)
        {
            var scopesForAudience = _scopeRepo.GetAll()
                .Where(s => s.Audience == audience)
                .Select(s => s.Name)
                .ToList();

            return ValidateScopes(clientId, scopesForAudience, out invalidScopes);
        }
    }


}
