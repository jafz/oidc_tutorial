using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace AuthorizationServer.Controllers;

// doesn't work with cookie in parallel without further ado
/*
 System.InvalidOperationException: The AuthorizationPolicy named: 'OpenIddict.Validation.AspNetCore' was not found.
OR....
 System.InvalidOperationException: The AuthorizationPolicy named: 'OpenIddict.Server.AspNetCore' was not found.
   at Microsoft.AspNetCore.Authorization.AuthorizationPolicy.CombineAsync(IAuthorizationPolicyProvider policyProvider, IEnumerable`1 authorizeData)
   at Microsoft.AspNetCore.Authorization.AuthorizationMiddleware.Invoke(HttpContext context)
   at Microsoft.AspNetCore.Authentication.AuthenticationMiddleware.Invoke(HttpContext context)
   at Microsoft.AspNetCore.Diagnostics.DeveloperExceptionPageMiddleware.Invoke(HttpContext context)
 */
// this doesn't work, it sets the policy, not the auth schemes
//[Authorize(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Route("api")]
public class ResourcesController : Controller
{
    [HttpGet("users")]
    [Produces("application/json")]
    public async Task<IActionResult> GetUsers()
    {
        /*
            System.InvalidOperationException: An identity cannot be extracted from this request.
            This generally indicates that the OpenIddict server stack was asked to validate a token for an endpoint it doesn't manage.
            To validate tokens received by custom API endpoints, the OpenIddict validation handler
            (e.g OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme or OpenIddictValidationOwinDefaults.AuthenticationType) must be used instead.
         */
        //var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        return Ok(User.Identity?.Name ?? "not authed");
    }
}
