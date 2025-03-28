using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System;

[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{
    [Authorize]
    [HttpGet]
    public IActionResult Get()
    {
        var claims = User.Claims
            .Select(c => $"{c.Type}: {c.Value}")
            .ToList();

        var response = string.Join(Environment.NewLine, claims);
        return Ok(response);
    }
}