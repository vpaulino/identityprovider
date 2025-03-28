using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace OidcClientApp.Controllers
{
    public class HomeController : Controller
    {

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly string _bffApiUrl;

        public HomeController(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpClientFactory = httpClientFactory;
            _bffApiUrl = configuration["Services:BffApi"];
        }

        public IActionResult Index() => View();

        [Authorize]
        public IActionResult Secure() => View();

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> CallApi()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");

            var client = _httpClientFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await client.GetAsync($"{_bffApiUrl}/api/secure");
            var content = await response.Content.ReadAsStringAsync();

            ViewData["ApiResponse"] = content;
            return View("Index");
        }
    }

}
