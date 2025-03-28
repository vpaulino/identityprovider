using System.Collections.Generic;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using IdentityProviderApi.Repositories;
using IdentityProviderApi.Scopes;
using static System.Formats.Asn1.AsnWriter;
namespace IdentityProviderApi.TokenGrantHandlers
{
    public class AuthorizationCodeGrantHandler : ITokenGrantHandler
    {
        public string GrantType => "authorization_code";

        private readonly IAuthCodeRepository _codeRepo;
        private readonly JwtTokenGenerator _tokenGenerator;
        private readonly IUserClientRoleRepository userClientRoleRepo;
        private readonly IScopeRepository scopeRepository;
        private readonly IScopeValidator _scopeValidator;
        public AuthorizationCodeGrantHandler(IAuthCodeRepository codeRepo, IUserClientRoleRepository userClientRoleRepo, JwtTokenGenerator tokenGenerator, IScopeRepository scopeRepository, IScopeValidator scopeValidator)
        {
            _codeRepo = codeRepo;
            _tokenGenerator = tokenGenerator;
            this.userClientRoleRepo = userClientRoleRepo;
            this.scopeRepository = scopeRepository;
            this._scopeValidator = scopeValidator;
        }

        private string GenerateAccessToken(HttpContext context, AuthCodeInfo storedCode)
        {
            var issuer = $"{context.Request.Scheme}://{context.Request.Host.Value}";

            var audience = ResolveAudienceFromScopes(storedCode.Scopes)
                ?? storedCode.Audience
                ?? storedCode.ClientId;

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, storedCode.Subject),
                new(JwtRegisteredClaimNames.Iss, issuer),
                   new(JwtRegisteredClaimNames.Aud, audience), // 🔁 support OBO targeting
                new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds().ToString())
            };

            foreach (var scope in storedCode.Scopes)
                claims.Add(new Claim("scope", scope));

            var roles = userClientRoleRepo.GetRoles(storedCode.ClientId, storedCode.Subject);
            foreach (var role in roles)
                claims.Add(new Claim("roles", role));

            return _tokenGenerator.CreateToken(claims);
        }

        /// <summary>
        /// Resolves the target audience (API) based on the list of requested scopes.
        /// 
        /// In OAuth 2.0 and OpenID Connect, access tokens include an "aud" (audience) claim,
        /// which identifies the resource server(s) the token is intended for.
        /// 
        /// This method inspects the list of scopes requested by the client and attempts to find
        /// the first scope that is registered with an associated audience. This is useful when
        /// a client (like a website) needs a token that will be accepted by a downstream API
        /// (like a BFF or backend service).
        /// 
        /// Note: While JWT allows "aud" to be an array (multi-audience), most identity providers
        /// and APIs assume a single audience per token for clarity and security. This method
        /// follows that model by resolving and returning only the first matching audience.
        /// </summary>
        /// <param name="scopes">The list of scopes requested by the client.</param>
        /// <returns>
        /// The audience (clientId) associated with the first matching scope,
        /// or null if no matching scope is found.
        /// </returns>
        private string? ResolveAudienceFromScopes(List<string> scopes)
        {
            foreach (var scope in scopes)
            {
                var definition = scopeRepository.Get(scope);
                if (definition is not null)
                    return definition.Audience;
            }

            return null;
        }

        private string GenerateIdToken(HttpContext context, AuthCodeInfo storedCode)
        {
            var issuer = $"{context.Request.Scheme}://{context.Request.Host.Value}";

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, storedCode.Subject),
                new(JwtRegisteredClaimNames.Aud, storedCode.ClientId),
                new(JwtRegisteredClaimNames.Iss, issuer),
                new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
                new(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds().ToString())
            };

            if (!string.IsNullOrEmpty(storedCode.Nonce))
            {
                claims.Add(new Claim(JwtRegisteredClaimNames.Nonce, storedCode.Nonce));
            }

            if (storedCode.Scopes.Contains("email"))
                claims.Add(new Claim(ClaimTypes.Email, "user@email.com")); // ideally from user store

            if (storedCode.Scopes.Contains("profile"))
                claims.Add(new Claim(ClaimTypes.Name, "Example User")); // also from user store

            var authTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            claims.Add(new Claim("auth_time", context.User.FindFirst("auth_time")?.Value ?? authTime));


            return _tokenGenerator.CreateToken(claims);
        }



        public async Task<IResult> HandleAsync(HttpContext context)
        {
            if (!context.Request.HasFormContentType)
                return Results.BadRequest("Expected x-www-form-urlencoded content");

            var form = await context.Request.ReadFormAsync();
            var grantType = form["grant_type"].ToString();
            var code = form["code"].ToString();
            var clientId = form["client_id"].ToString();
            var redirectUri = form["redirect_uri"].ToString();

            if (grantType != "authorization_code")
                return Results.BadRequest("Unsupported grant_type");

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
                return Results.BadRequest("Missing required parameters");

            var storedCode = _codeRepo.Get(code);
            if (storedCode is null)
                return Results.BadRequest("Invalid or expired authorization code");

            if (storedCode.ClientId != clientId || storedCode.RedirectUri != redirectUri)
                return Results.BadRequest("Client ID or redirect URI mismatch");

            if (storedCode.ExpiresAt < DateTime.UtcNow)
                return Results.BadRequest("Authorization code has expired");

            _codeRepo.Remove(code); // Single-use code
            
            // match if the scope being asked are allowed in the registration of that scopes for that client.
            if (!_scopeValidator.ValidateScopes(clientId, storedCode.Scopes, out var invalid))
            {
                return Results.BadRequest($"Client is not allowed to request scopes: {string.Join(", ", invalid)}");
            }

            var idToken = GenerateIdToken(context, storedCode);
            var accessToken = GenerateAccessToken(context, storedCode);

            return Results.Ok(new
            {
                id_token = idToken,
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = 3600
            });
        }
 
    }

}
