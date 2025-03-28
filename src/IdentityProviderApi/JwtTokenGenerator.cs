using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

public record SigningKeyInfo(string Modulus, string Exponent, string Kid, string Algorithm);

public class JwtTokenGenerator : IDisposable
{
    public string Authority { get; }
    public string Audience { get; }

    private readonly RSA _rsa;
    private readonly SigningCredentials _signingCredentials;
    private readonly string _kid;

    public JwtTokenGenerator(string authority, string audience)
    {
        Authority = authority;
        Audience = audience;
        _kid = Guid.NewGuid().ToString("N");
        _rsa = RSA.Create(2048);
        _signingCredentials = new SigningCredentials(
            new RsaSecurityKey(_rsa) { KeyId = _kid },
            SecurityAlgorithms.RsaSha256
        );
    }

    public SigningKeyInfo GetSigningKeyInfo()
    {
        var parameters = _rsa.ExportParameters(false);
        return new SigningKeyInfo(
            Base64UrlEncode(parameters.Modulus!),
            Base64UrlEncode(parameters.Exponent!),            
            _kid,
            SecurityAlgorithms.RsaSha256
        );
    }

    public string CreateToken(IReadOnlyList<Claim>? customClaims = null, DateTime? expiresAt = null)
    {
        var claims = new List<Claim>();
    

        if (customClaims != null)
            claims.AddRange(customClaims);

        var tokenHandler = new JwtSecurityTokenHandler();
        var securityToken = tokenHandler.CreateJwtSecurityToken(
            issuer: $"{customClaims.FirstOrDefault((claim) => claim.Type.Equals(JwtRegisteredClaimNames.Iss.ToLower())).Value}",
            audience: customClaims.FirstOrDefault((claim)=> claim.Type.Equals(JwtRegisteredClaimNames.Aud.ToLower())).Value,
            subject: new ClaimsIdentity(claims),
            expires: expiresAt ?? DateTime.UtcNow.AddHours(1),
            signingCredentials: _signingCredentials
        );

        return tokenHandler.WriteToken(securityToken);
    }


    private static string Base64UrlEncode(byte[] input)
        => Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public void Dispose() => _rsa.Dispose();
}