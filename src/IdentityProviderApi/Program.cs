using IdentityProviderApi.Repositories;
using IdentityProviderApi.Scopes;
using IdentityProviderApi.TokenGrantHandlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<JwtTokenGenerator>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var authority = config["Authority"]!;
    var audience = config["Audience"]!;
    return new JwtTokenGenerator(authority, audience);
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login"; // default redirect if user is not authenticated
        options.Cookie.Name = "idp-auth"; // optional: custom name for clarity
    });

builder.Services.AddAuthorization();

builder.Services.AddSingleton<IUserClientRoleRepository, InMemoryUserClientRoleRepository>();
builder.Services.AddSingleton<IClientRepository, InMemoryClientRepository>();
builder.Services.AddSingleton<IUserStore, InMemoryUserStore>();
builder.Services.AddSingleton<IAuthCodeRepository, InMemoryAuthCodeRepository>();
builder.Services.AddSingleton<IScopeRepository, InMemoryScopeRepository>();

builder.Services.AddSingleton<IScopeValidator,ScopeValidator>();

builder.Services.AddSingleton<ITokenValidator, TokenValidator>();
builder.Services.AddSingleton<ITokenGrantHandler, AuthorizationCodeGrantHandler>();
builder.Services.AddSingleton<ITokenGrantHandler, OnBehalfOfGrantHandler>();
builder.Services.AddSingleton<TokenEndpointHandler>();



builder.Services.AddControllers();
var app = builder.Build();

app.MapPost("/users", ([FromBody] User user, [FromServices] IUserStore userStore) =>
{
    if (string.IsNullOrEmpty(user.SubjectId))
        return Results.BadRequest("SubjectId is required");

    // For simplicity, overwrite if it already exists
    userStore.Add(user);
    return Results.Created($"/users/{user.SubjectId}", user);
});

app.MapGet("/users", ([FromServices] IUserStore userStore) => userStore.GetAll());


app.MapPost("/clients", ([FromServices] IClientRepository repo, [FromBody] OAuthClient client) =>
{
    repo.Add(client);
    return Results.Created($"/clients/{client.ClientId}", client);
});

app.MapPost("/user-roles", (
           [FromBody] UserClientRole role,
           IClientRepository clientRepo,
           IUserStore userStore,
           IUserClientRoleRepository roleRepo
       ) =>
{
    if (string.IsNullOrWhiteSpace(role.ClientId) ||
        string.IsNullOrWhiteSpace(role.SubjectId) ||
        string.IsNullOrWhiteSpace(role.Role))
    {
        return Results.BadRequest("ClientId, SubjectId, and Role are required.");
    }

    if (clientRepo.Get(role.ClientId) is null)
    {
        return Results.BadRequest($"ClientId '{role.ClientId}' does not exist.");
    }

    if (userStore.Get(role.SubjectId) is null)
    {
        return Results.BadRequest($"User with SubjectId '{role.SubjectId}' does not exist.");
    }

    roleRepo.Add(role);
    return Results.Created($"/user-roles/{role.ClientId}/{role.SubjectId}", role);
});

app.MapPost("/scopes", (
    [FromBody] ScopeDefinition scope,
    [FromServices] IScopeRepository repo,
    [FromServices] IClientRepository clientRepo) =>
{
    if (string.IsNullOrWhiteSpace(scope.Name) || string.IsNullOrWhiteSpace(scope.Audience))
        return Results.BadRequest("Scope name and audience are required.");

    var client = clientRepo.Get(scope.Audience);
    if (client is null)
        return Results.BadRequest($"Audience '{scope.Audience}' is not a registered client/application.");

    repo.Add(scope);
    return Results.Created($"/scopes/{scope.Name}", scope);
});

app.MapGet("/scopes", ([FromServices] IScopeRepository repo) =>
{
    return Results.Ok(repo.GetAll());
});


// Show login form
app.MapGet("/login", (HttpRequest req) =>
{
    var returnUrl = req.Query["ReturnUrl"].ToString() ?? "/";
    var html = $"""
        <form method="post" action="/login?returnUrl={Uri.EscapeDataString(returnUrl)}">
            <label>Username: <input name="username" /></label>
            <button type="submit">Login</button>
        </form>
    """;
    return Results.Content(html, "text/html");
});

// Handle login
app.MapPost("/login", async (HttpContext context, [FromServices] IUserStore userStore) =>
{
    var form = await context.Request.ReadFormAsync();
    var username = form["username"].ToString();

    var user = userStore.Get(username);
    if (user is null)
        return Results.BadRequest("User not found");

    var authTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.SubjectId),
        new(ClaimTypes.Name, user.Name),
        new(ClaimTypes.Email, user.Email),
         new("auth_time", authTime)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

    var returnUrl = context.Request.Query["returnUrl"].ToString() ?? "/";
    return Results.Redirect(returnUrl);
});


app.MapGet("/.well-known/openid-configuration", (HttpContext context) =>
{
    var request = context.Request;
    var host = $"{request.Scheme}://{request.Host}";

    var config = new
    {
        issuer = host,
        authorization_endpoint = $"{host}/authorize",
        token_endpoint = $"{host}/token",
        userinfo_endpoint = $"{host}/userinfo",
        jwks_uri = $"{host}/.well-known/jwks.json",
        response_types_supported = new[] { "code", "token", "id_token" },
        subject_types_supported = new[] { "public" },
        id_token_signing_alg_values_supported = new[] { "RS256" },
        scopes_supported = new[] { "openid", "profile", "email", "offline_access" },
        token_endpoint_auth_methods_supported = new[] { "client_secret_post", "none" }
    };

    return Results.Json(config);
});


app.MapGet("/authorize", [Authorize] async (    HttpContext context,    IAuthCodeRepository codeRepo,    IClientRepository clientRepo,    IUserClientRoleRepository roleRepo) =>
{
    var query = context.Request.Query;
 

    string? TryGet(string key) =>
        query.TryGetValue(key, out var value) ? value.ToString() : null;

    int? TryGetInt(string key)
    {
        if (query.TryGetValue(key, out var value) && int.TryParse(value, out var intValue))
            return intValue;
        return null;
    }

    var clientId = TryGet("client_id") ?? throw new Exception("Missing client_id");
    var redirectUri = TryGet("redirect_uri") ?? throw new Exception("Missing redirect_uri");
    var responseType = TryGet("response_type") ?? throw new Exception("Missing response_type");
    var scope = TryGet("scope");
    

    var state = TryGet("state");
    var nonce = TryGet("nonce");
    var prompt = TryGet("prompt");
    var loginHint = TryGet("login_hint");
    var maxAge = TryGetInt("max_age");

    var scopes = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();


    // Validate required parameters
    if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri) || string.IsNullOrEmpty(responseType))
        return Results.BadRequest("Missing required parameters.");

    // Validate client and redirect URI
    var client = clientRepo.Get(clientId);
    if (client is null || client.RedirectUri != redirectUri)
        return Results.BadRequest("Invalid client or redirect URI mismatch.");

    var isAuthenticated = context.User.Identity?.IsAuthenticated ?? false;
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    if (prompt == "login")
    {
        // Force re-login
        var returnUrl = context.Request.Path + context.Request.QueryString;
        return Results.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
    }

    if (maxAge.HasValue)
    {
        var authTime = context.User.FindFirst("auth_time")?.Value;
        if (authTime != null && long.TryParse(authTime, out var authTimestamp))
        {
            if ((now - authTimestamp) > maxAge.Value)
            {
                var returnUrl = context.Request.Path + context.Request.QueryString;
                return Results.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
            }
        }
    }

    if (!isAuthenticated && prompt == "none")
    {
        // Spec: don't show UI, but user is not logged in
        var errorRedirect = $"{redirectUri}?error=login_required&state={state}";
        return Results.Redirect(errorRedirect);
    }


    // Get logged-in user identity
    var subject = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    if (string.IsNullOrEmpty(subject))
        return Results.BadRequest("Authenticated user subject not found.");

    // Check if the user has any roles in the application (client)
    var roles = roleRepo.GetRoles(clientId, subject);
    if (!roles.Any())
    {
        // Redirect back to the client with access_denied error
        var errorRedirect = $"{redirectUri}?error=access_denied&error_description=User%20not%20authorized&state={state}";
        return Results.Redirect(errorRedirect); // 302 Found
    }

    // All good, issue the authorization code
    var code = Guid.NewGuid().ToString("N");

    codeRepo.Store(new AuthCodeInfo(
       Code: code,
       ClientId: clientId,
       RedirectUri: redirectUri,
       Scopes: scopes,
       Subject: subject,
       ExpiresAt: DateTime.UtcNow.AddMinutes(5),
       Nonce: nonce,
       State: state,
       Prompt: prompt,
       LoginHint: loginHint,
       MaxAge: maxAge,
       Audience : null
   ));


    var redirectUrl = $"{redirectUri}?code={code}&state={state}";
    return Results.Redirect(redirectUrl); // 302 Found
});


app.MapPost("/token", async (HttpContext context, [FromServices] TokenEndpointHandler handler) =>
{
    return await handler.HandleTokenRequest(context);
});

//https://mojoauth.com/blog/understanding-the-oidc-json-web-key-jwk-endpoint-in-authentication/
app.MapGet("/.well-known/jwks.json", ([FromServices] JwtTokenGenerator generator) =>
{
    var keyInfo = generator.GetSigningKeyInfo();
    return Results.Json(new
    {
        keys = new[]
        {
            new {
                kty = "RSA",
                use = "sig",
                kid = keyInfo.Kid,
                alg = keyInfo.Algorithm,
                n = keyInfo.Modulus,
                e = keyInfo.Exponent
            }
        }
    });
});

app.Run();

record ClaimDto(string Type, string Value);