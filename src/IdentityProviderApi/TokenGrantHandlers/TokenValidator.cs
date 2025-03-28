namespace IdentityProviderApi.TokenGrantHandlers
{
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.Logging;
    using System.Threading.Tasks;
    using System.Threading;
    using Microsoft.IdentityModel.Protocols;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.IdentityModel.Tokens;

    public interface ITokenValidator
    {
        Task<ClaimsPrincipal?> ValidateTokenAsync(string token);
    }

    public class TokenValidator : ITokenValidator
    {
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager;
        private readonly ILogger<TokenValidator> _logger;

        public TokenValidator(IConfiguration configuration, ILogger<TokenValidator> logger)
        {
            var authority = configuration["Authorization:Authority"]
                ?? throw new ArgumentNullException("Authorization:Authority not found in config.");

            var metadataAddress = $"{authority}/.well-known/openid-configuration";
            _configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                metadataAddress,
                new OpenIdConnectConfigurationRetriever()
            );

            _logger = logger;
        }

        public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token)
        {
            var config = await _configManager.GetConfigurationAsync(CancellationToken.None);

            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = config.Issuer,

                ValidateAudience = false, // You may want to toggle this
                ValidateLifetime = true,
                RequireSignedTokens = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = config.SigningKeys
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ValidateToken(token, validationParams, out _);
                return principal;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Token validation failed: {Message}", ex.Message);
                return null;
            }
        }
    }

}
