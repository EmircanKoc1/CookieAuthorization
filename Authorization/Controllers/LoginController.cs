using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Authorization.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        [HttpGet("[action]")]
        [AllowAnonymous]
        public async Task<IActionResult> YoneticiSignIn()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,"Emir"),
                new Claim(ClaimTypes.Role,"Yonetici")
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authenticationProperties = new AuthenticationProperties();
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authenticationProperties);
            return Ok();
        }

        [HttpGet("[action]")]
        [AllowAnonymous]
        public async Task<IActionResult> UserSignIn()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,"Emir"),
                new Claim(ClaimTypes.Role,"User")
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authenticationProperties = new AuthenticationProperties();
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authenticationProperties);
            return Ok();
        }

        [HttpGet("[action]")]
      
        public async Task<IActionResult> UserAndYoneticiSignIn()
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,"Emir"),
                new Claim(ClaimTypes.Role,"User"),
                new Claim(ClaimTypes.Role,"Yonetici")
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authenticationProperties = new AuthenticationProperties();
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authenticationProperties);
            return Ok();
        }

        [HttpGet("[action]")]
        [Authorize(Policy ="CombinedPolicy")]
        public IActionResult CombinedPolicy()
        {

            return Ok();
        }

        [HttpGet("[action]")]
        [Authorize(Policy = "CombinedPolicy2")]
        public IActionResult CombinedPolicy2()
        {

            return Ok();
        }


        [HttpGet("[action]")]
        [Authorize(Policy = "YoneticiRoluAra")]
        public IActionResult AuthorizeYonetici()
        {
            return Ok();
        }

        [HttpGet("[action]")]
        [Authorize(Roles = "User")]
        public IActionResult AuthorizeUser()
        {
            return Ok();
        }
        [HttpGet("[action]")]
        [Authorize(Roles = "User")]
        [Authorize(Roles = "Yonetici")]
        public IActionResult AuthorizeUserAndYonetici()
        {
            return Ok();
        }

        [HttpGet("[action]")]
        [Authorize(Policy = "ClaimPolicy")]
        public IActionResult ClaimPolicy()
        {
            return Ok();
        }
        [HttpGet("[action]")]
        public async Task<IActionResult> AvakadoSignIn()
        {
            var claims = new List<Claim>
            {
                new Claim("Avakado","meyve")
            };
            var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authenticationProperties = new AuthenticationProperties();
            var claimPrincipal = new ClaimsPrincipal(claimIdentity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimPrincipal, authenticationProperties);


            return Ok();
        }
        [HttpGet("[action]")]
        [Authorize(Policy = "ClaimValuePolicy")]
        public IActionResult ClaimValuePolicy()
        {
            return Ok();
        }
        [HttpGet("[action]")]
        public async Task<IActionResult> AvakadoValueSignIn()
        {
            var claims = new List<Claim>
            {
                new Claim("Avakado","sebzedir")
            };
            var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authenticationProperties = new AuthenticationProperties();
            var claimPrincipal = new ClaimsPrincipal(claimIdentity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimPrincipal, authenticationProperties);

            return Ok();
        }

        [HttpGet("[action]")]
        public IActionResult Index()
        {
            return Ok();
        }

        [HttpGet("[action]")]
        public async Task<IActionResult> CikisYap()
        {
            await HttpContext.SignOutAsync();
            return Ok();
        }

    }
}
