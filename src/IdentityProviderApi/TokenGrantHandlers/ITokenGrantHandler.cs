using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;

namespace IdentityProviderApi.TokenGrantHandlers
{
    public interface ITokenGrantHandler
    {
        string GrantType { get; }
        Task<IResult> HandleAsync(HttpContext context);
    }
}
