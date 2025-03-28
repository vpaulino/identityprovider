using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    [HttpGet("/signin")]
    public IActionResult SignIn() => Challenge(new AuthenticationProperties { RedirectUri = "/" }, "oidc");

    [HttpPost("/signout"), ValidateAntiForgeryToken]
    public IActionResult Logout()
    {
        return SignOut(new AuthenticationProperties { RedirectUri = "/" },
            CookieAuthenticationDefaults.AuthenticationScheme,
            "oidc");
    }
}