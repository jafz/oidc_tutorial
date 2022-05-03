using AuthorizationServer.ViewModels;
using ConsoleApp1;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using System.Security.Claims;
using System.Security.Principal;

namespace AuthorizationServer.Controllers
{
    public class AccountController : Controller
    {
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }


        public static void AddClaims(ClaimsIdentity identity)
        {
            var current = WindowsIdentity.GetCurrent();

            identity.AddClaims(current.Claims.Select(x =>
            {
                x.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                return x;
            }));
            identity.AddClaim(new Claim("name", "postman").SetDestinations(OpenIddictConstants.Destinations.AccessToken));
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            ViewData["ReturnUrl"] = model.ReturnUrl;

            if (ModelState.IsValid)
            {
                IList<DtoEnvironmentClaim> environmentClaims;
                if (model.Username == "local")
                {
                    var current = WindowsIdentity.GetCurrent();
                    environmentClaims = new List<DtoEnvironmentClaim>();
                    var sid = current.Claims.First(x => x.Type == ClaimTypes.PrimarySid);
                    environmentClaims.Add(new DtoEnvironmentClaim { Name = current.Name, Type = DtoClaimType.User, SID = sid.Value });
                    foreach (var currentClaim in current.Claims)
                    {
                        if (currentClaim.Type == ClaimTypes.GroupSid || currentClaim.Type == ClaimTypes.PrimaryGroupSid)
                        {
                            environmentClaims.Add(new DtoEnvironmentClaim { SID = currentClaim.Value, Type = DtoClaimType.Group });
                        }
                    }
                }
                else
                {
                    environmentClaims = OAuthHelper.Verify(model.Username, model.Password);
                }
                var userClaim = environmentClaims.FirstOrDefault(x => x.Type == DtoClaimType.User);
                var name = userClaim?.Name ??
                           model.Username;
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, name)
                };

                foreach (var role in environmentClaims)
                {
                    switch (role.Type)
                    {
                        case DtoClaimType.User:
                            claims.Add(new Claim(ClaimTypes.PrimarySid, role.SID));
                            break;
                        case DtoClaimType.Group:
                            claims.Add(new Claim(ClaimTypes.Sid, role.SID));
                            break;
                        case DtoClaimType.Scope:
                            claims.Add(new Claim("scope", role.Name));
                            break;
                        default:
                            break;
                    }

                }

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

                await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));

                if (Url.IsLocalUrl(model.ReturnUrl))
                {
                    return Redirect(model.ReturnUrl);
                }

                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View(model);
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync();

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }
    }
}
