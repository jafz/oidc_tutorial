using Microsoft.AspNetCore.Authorization;
using OpenIddict.Validation.AspNetCore;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddLogging(opt =>
{
    opt.AddSimpleConsole(opt => opt.TimestampFormat = "[HH:mm:ss] ");
});

builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        // Note: the validation handler uses OpenID Connect discovery
        // to retrieve the address of the introspection endpoint
        options.SetIssuer("https://localhost:44369");
        options.AddAudiences("resource_server_1");

        // Configure the validation handler to use introspection and register the client
        // credentials used when communicating with the remote introspection endpoint
        options.UseIntrospection()
        .SetClientId("resource_server_1")
        .SetClientSecret("846B62D0-DEF9-4215-A99D-86E6B8DAB342");

        options.UseSystemNetHttp();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api", [Authorize] (ClaimsPrincipal user) => $"{user.Identity!.Name} says hello and can access resource 1");
app.MapGet("/", () => $"Resource 1 says hello");

app.Run();
