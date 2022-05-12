using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthorizationServer.Controllers
{
    public class AuthorizationController : Controller
    {
        private readonly ILogger _logger;
        private readonly IOpenIddictScopeManager _manager;

        public AuthorizationController(ILogger<AuthorizationController> logger, IOpenIddictScopeManager manager)
        {
            _logger = logger;
            _manager = manager;
        }

        [HttpPost("~/connect/token"), Produces("application/json")]
        public async Task<IActionResult> ExchangeToken()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            ClaimsPrincipal claimsPrincipal;
            _logger.LogWarning("Get token via {grant} grant", request.GrantType);

            if (request.IsClientCredentialsGrantType())
            {
                // Note: the client credentials are automatically validated by OpenIddict:
                // if client_id or client_secret are invalid, this action won't be invoked.

                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                // Subject (sub) is a required field, we use the client id as the subject identifier here.
                identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException());

                // Add some claim, don't forget to add destination otherwise it won't be added to the access token.
                identity.AddClaim("some-claim idTOK", "for ID token", OpenIddictConstants.Destinations.IdentityToken);
                identity.AddClaim("some-claim2", "for access token", OpenIddictConstants.Destinations.AccessToken);
                identity.AddClaim("some-claim2", "somewhat", OpenIddictConstants.Destinations.AccessToken);
                identity.AddClaim("some-claim2", "megagirl", OpenIddictConstants.Destinations.AccessToken);
                for (int i = 0; i < 10; i++)
                {
                    identity.AddClaim($"superClaim {i}", "value " + i, OpenIddictConstants.Destinations.IdentityToken, OpenIddictConstants.Destinations.AccessToken);
                }

                if (request.ClientId == "postman")
                {
                    AccountController.AddClaims(identity);
                }

                claimsPrincipal = new ClaimsPrincipal(identity);

                var scopes = request.GetScopes();
                var s = scopes.AddRange(new[] { "unattended", "interactive" });
                claimsPrincipal.SetScopes(s);
                claimsPrincipal.SetResources("postman", "resource_server_1");
            }
            else if (request.IsAuthorizationCodeGrantType())
            {

                var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                if (authResult.Principal == null)
                    throw new InvalidOperationException("Failed to authenticate user");
                claimsPrincipal = authResult.Principal;
            }
            else if (request.IsRefreshTokenGrantType())
            {
                // Retrieve the claims principal stored in the refresh token.
                var authenticateResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                if (authenticateResult.Principal == null)
                    throw new InvalidOperationException("Failed to authenticate user");
                claimsPrincipal = authenticateResult.Principal;
            }
            else if (request.IsPasswordGrantType())
            {
                var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                AccountController.AddClaims(identity);
                identity.AddClaim("some-claim2", "somewhat", OpenIddictConstants.Destinations.AccessToken, Destinations.IdentityToken);
                identity.AddClaim("some-claim2", "megagirl", OpenIddictConstants.Destinations.AccessToken, Destinations.IdentityToken);

                var subject = identity.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name)?.Value ?? "harald";
                identity.AddClaim(Claims.Subject, subject);
                claimsPrincipal = new ClaimsPrincipal(identity);
                claimsPrincipal.SetScopes("offline_access", "api", "openid");

                // Note: the client credentials are automatically validated by OpenIddict:
                // if client_id or client_secret are invalid, this action won't be invoked.

                //identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

                //// Subject (sub) is a required field, we use the client id as the subject identifier here.
                //identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException());

                //// Add some claim, don't forget to add destination otherwise it won't be added to the access token.
                //identity.AddClaim("some-claim idTOK", "for ID token", OpenIddictConstants.Destinations.IdentityToken);
                //identity.AddClaim("some-claim2", "for access token", OpenIddictConstants.Destinations.AccessToken);
                //identity.AddClaim("some-claim2", "somewhat", OpenIddictConstants.Destinations.AccessToken);
                //identity.AddClaim("some-claim2", "megagirl", OpenIddictConstants.Destinations.AccessToken);
                //for (int i = 0; i < 10; i++)
                //{
                //    identity.AddClaim($"superClaim {i}", "value " + i, OpenIddictConstants.Destinations.IdentityToken, OpenIddictConstants.Destinations.AccessToken);
                //}

                //if (request.ClientId == "postman")
                //{
                //    AccountController.AddClaims(identity);
                //}

                //claimsPrincipal = new ClaimsPrincipal(identity);

                //var scopes = request.GetScopes();
                //var s = scopes.AddRange(new[] { "unattended", "interactive" });
                //claimsPrincipal.SetScopes(s);
                //claimsPrincipal.SetResources("postman", "resource_server_1");
            }
            else
            {
                throw new InvalidOperationException("The specified grant type is not supported.");
            }

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        private async Task<IActionResult> HandleHardcodedIdentifierAsync(OpenIddictRequest request)
        {
            var identifier = (int?)request["hardcoded_identity_id"];
            if (identifier is not (1 or 2))
            {
                var props = new Dictionary<string, string>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidRequest,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The specified hardcoded identity is invalid."
                };

                return Challenge(
                    properties: new AuthenticationProperties(props!),
                    authenticationSchemes: new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme }
                    );
            }

            // Create a new identity and populate it based on the specified hardcoded identity identifier.
            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
            identity.AddClaim(new Claim(Claims.Subject, identifier.Value.ToString(CultureInfo.InvariantCulture)));
            identity.AddClaim(new Claim(Claims.Name, identifier switch
            {
                1 => "Alice",
                2 => "Bob",
                _ => throw new InvalidOperationException()
            }).SetDestinations(Destinations.AccessToken));

            // Note: in this sample, the client is granted all the requested scopes for the first identity (Alice)
            // but for the second one (Bob), only the "api1" scope can be granted, which will cause requests sent
            // to Zirku.Api2 on behalf of Bob to be automatically rejected by the OpenIddict validation handler,
            // as the access token representing Bob won't contain the "resource_server_2" audience required by Api2.
            var principal = new ClaimsPrincipal(identity);

            principal.SetScopes(identifier switch
            {
                1 => request.GetScopes(),
                2 => new[] { "api1" }.Intersect(request.GetScopes()),
                _ => throw new InvalidOperationException()
            });

            var allResources = _manager.ListResourcesAsync(principal.GetScopes());
            List<string> all = new List<string>();
            await foreach (var item in allResources)
            {
                all.Add(item);
            }

            principal.SetResources(all);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Authorize()
        {
            // https://dev.to/robinvanderknaap/setting-up-an-authorization-server-with-openiddict-part-iv-authorization-code-flow-3eh8
            var request = HttpContext.GetOpenIddictServerRequest() ??
                    throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var identifier = (int?)request["hardcoded_identity_id"];

            if (identifier is not null)
            {
                var retVal = await HandleHardcodedIdentifierAsync(request);
                return retVal;
            }

            // Retrieve the user principal stored in the authentication cookie.
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // If the user principal can't be extracted, redirect the user to the login page.
            if (!result.Succeeded)
            {
                var redirectUri = Request.PathBase + Request.Path + QueryString.Create(
                            Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList());
                var challenge = Challenge(
                    authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties
                    {
                        RedirectUri = redirectUri
                    });
                _logger.LogWarning("Authorization requested. User is not yet authenticated. Redirecting to {redirectUri}", redirectUri);
                return challenge;
            }

            if (result.Principal.Identity == null || result.Principal.Identity.Name == null)
                throw new InvalidOperationException("Can't have empty principal");

            _logger.LogWarning("Authorization requested. User {user} requests access code", result.Principal);
            // Create a new claims principal
            var claims = new List<Claim>
            {
                // 'subject' claim which is required
                new Claim(OpenIddictConstants.Claims.Subject, result.Principal.Identity.Name),
                new Claim(OpenIddictConstants.Claims.Name, result.Principal.Identity.Name).SetDestinations(Destinations.AccessToken),
                new Claim("some claim", "some value").SetDestinations(OpenIddictConstants.Destinations.AccessToken),
                new Claim("scopes_test", "some_value, other, other, yet").SetDestinations(OpenIddictConstants.Destinations.AccessToken),
                new Claim(OpenIddictConstants.Claims.Email, "some@email").SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken),
                new Claim("scope", "unattended").SetDestinations(Destinations.AccessToken),
                new Claim("scope", "interactive").SetDestinations(Destinations.AccessToken),
            };
            claims.AddRange(result.Principal.Claims.Select(x =>
            {
                x.SetDestinations(Destinations.AccessToken);
                return x;
            }));

            var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            // Set requested scopes (this is not done automatically)
            claimsPrincipal.SetScopes(request.GetScopes());
            claimsPrincipal.SetResources("postman", "resource_server_1");
            claimsPrincipal.SetClaims("scopes_test2", new[] { "scome_value", "youyo", "yolo" }.ToImmutableArray());
            foreach (var cc in claimsPrincipal.Claims.Where(x => x.Type == "scopes_test2"))
            {
                cc.SetDestinations(Destinations.AccessToken);
            }

            // Signing in with the OpenIddict authentiction scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
            var signIn = SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            return signIn;
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo")]
        public async Task<IActionResult> Userinfo()
        {
            var authResult = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var claimsPrincipal = authResult.Principal;
            if (claimsPrincipal == null)
                throw new InvalidOperationException("No user info b/c there is no claims principal");

            return Ok(new
            {
                Name = claimsPrincipal.GetClaim(OpenIddictConstants.Claims.Subject),
                Occupation = "Developer",
                Age = 43
            });
        }
    }
}
