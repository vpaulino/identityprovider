using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System;
using System.Threading.Tasks;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text.Json;
using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;

[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public SecureController(IHttpClientFactory httpClientFactory, IHttpContextAccessor httpContextAccessor)
    {
        _httpClientFactory = httpClientFactory;
        _httpContextAccessor = httpContextAccessor;
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        var claims = User.Claims
      .Select(c => $"{c.Type}: {c.Value}")
      .ToList();

        var backendResult = await CallBackendOnBehalfOfUser();

        claims.Add("");
        claims.Add("------ OBO Backend Call Result ------");
        claims.Add(backendResult ?? "⚠️ No result");

        var response = string.Join(Environment.NewLine, claims);
        return Ok(response);
    }

    private async Task<string?> CallBackendOnBehalfOfUser()
    {
        var originalToken = await _httpContextAccessor.HttpContext!.GetTokenAsync("access_token");
        if (string.IsNullOrEmpty(originalToken))
            return "❌ No access token available";

        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer",
            ["client_id"] = "bffapi-clientid",
            ["requested_token_use"] = "on_behalf_of",
            ["audience"] = "backendapi-clientid",
            ["assertion"] = originalToken
        };

        var tokenClient = _httpClientFactory.CreateClient();
        var tokenResponse = await tokenClient.PostAsync("https://localhost:56519/token", new FormUrlEncodedContent(form));
        if (!tokenResponse.IsSuccessStatusCode)
            return $"❌ Token request failed: {tokenResponse.StatusCode}";

        var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
        var newToken = JsonDocument.Parse(tokenJson)
            .RootElement.GetProperty("access_token").GetString();

        var backendClient = _httpClientFactory.CreateClient();
        backendClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", newToken);

        var backendResponse = await backendClient.GetAsync("https://localhost:8080/api/Secure");
        var content = await backendResponse.Content.ReadAsStringAsync();

        return $"✅ Backend API response:\n{content}";
    }

}