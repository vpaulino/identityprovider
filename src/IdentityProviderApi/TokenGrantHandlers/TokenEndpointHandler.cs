using IdentityProviderApi.TokenGrantHandlers;
using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

public class TokenEndpointHandler
{
    private readonly IEnumerable<ITokenGrantHandler> _handlers;

    public TokenEndpointHandler(IEnumerable<ITokenGrantHandler> handlers)
    {
        _handlers = handlers;
    }

    public async Task<IResult> HandleTokenRequest(HttpContext context)
    {
        var form = await context.Request.ReadFormAsync();
        var grantType = form["grant_type"].ToString();

        var handler = _handlers.FirstOrDefault(h => h.GrantType == grantType);
        if (handler is null)
            return Results.BadRequest($"Unsupported grant_type: {grantType}");

        return await handler.HandleAsync(context);
    }
}
