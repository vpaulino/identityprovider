using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace IdentityProviderApi.TokenGrantHandlers
{
    using System.Security.Claims;
    using Microsoft.AspNetCore.Http;
    using Microsoft.IdentityModel.Tokens;
    using System.IdentityModel.Tokens.Jwt;
    using System.Collections.Generic;
    using System;
    using IdentityProviderApi.Scopes;

    public class OnBehalfOfGrantHandler : ITokenGrantHandler
    {
        private readonly IClientRepository _clientRepo;
        private readonly IScopeValidator _scopeValidator;
        private readonly ITokenValidator _tokenValidator;
        private readonly JwtTokenGenerator _tokenGenerator;

        public OnBehalfOfGrantHandler(
            IClientRepository clientRepo,
            IScopeValidator scopeValidator,
            ITokenValidator tokenValidator,
            JwtTokenGenerator tokenGenerator)
        {
            _clientRepo = clientRepo;
            _scopeValidator = scopeValidator;
            _tokenValidator = tokenValidator;
            _tokenGenerator = tokenGenerator;
        }

        public string GrantType => "urn:ietf:params:oauth:grant-type:jwt-bearer";

        public async Task<IResult> HandleAsync(HttpContext context)
        {
            if (!context.Request.HasFormContentType)
                return Results.BadRequest("Expected x-www-form-urlencoded content");

            var form = await context.Request.ReadFormAsync();

            var assertion = form["assertion"].ToString();
            var clientId = form["client_id"].ToString();
            var audience = form["audience"].ToString();
            var requestedUse = form["requested_token_use"].ToString();

            if (string.IsNullOrEmpty(assertion) ||
                string.IsNullOrEmpty(clientId) ||
                string.IsNullOrEmpty(audience))
            {
                return Results.BadRequest("Missing required parameters");
            }

            if (requestedUse != "on_behalf_of")
            {
                return Results.BadRequest("Invalid or missing requested_token_use");
            }

            // ✅ Validate client exists
            var client = _clientRepo.Get(clientId);
            if (client is null)
            {
                return Results.BadRequest("Invalid client_id");
            }

            // ✅ Validate the client is allowed to request this audience
            if (!_scopeValidator.ValidateAudience(clientId, audience, out var invalid))
            {
                return Results.BadRequest(new
                {
                    error = "invalid_scope",
                    error_description = $"Client '{clientId}' is not allowed to request access to audience '{audience}'"
                });
            }

            // ✅ Validate the user's access token using the shared TokenValidator
            var principal = await _tokenValidator.ValidateTokenAsync(assertion);
            if (principal is null)
            {
                return Results.BadRequest("Token validation failed");
            }
            var sub =principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value ??
                principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (string.IsNullOrEmpty(sub))
            {
                return Results.BadRequest("Subject claim missing in assertion");
            }

            // ✅ Build the new token on behalf of the user
            var now = DateTimeOffset.UtcNow;
            var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, sub),
            new(JwtRegisteredClaimNames.Iss, $"{context.Request.Scheme}://{context.Request.Host.Value}"),
            new(JwtRegisteredClaimNames.Aud, audience),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString()),
            new(JwtRegisteredClaimNames.Exp, now.AddHours(1).ToUnixTimeSeconds().ToString())
        };

            // Optional: Copy scopes and roles from the original token
            foreach (var scope in principal.FindAll("scope"))
                claims.Add(scope);

            foreach (var role in principal.FindAll("roles"))
                claims.Add(role);

            var token = _tokenGenerator.CreateToken(claims);

            return Results.Ok(new
            {
                access_token = token,
                token_type = "Bearer",
                expires_in = 3600
            });
        }
    }



}
