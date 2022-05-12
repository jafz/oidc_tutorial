using AuthorizationServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;
using System.Security.Claims;

public static class JakobExtensions
{
    public static WebApplicationBuilder AddSimpleConsoleLogging(this WebApplicationBuilder builder)
    {
        builder.Services.AddLogging(opt =>
        {
            opt.AddSimpleConsole(opt => opt.TimestampFormat = "[HH:mm:ss] ");
        });

        return builder;
    }
    public static WebApplicationBuilder AddSerilog(this WebApplicationBuilder builder)
    {
        Log.Logger = new LoggerConfiguration()
            // serilog doesn't use the appsettings Logging config
            .MinimumLevel.Override("Default", LogEventLevel.Information)
            .MinimumLevel.Override("Microsoft.AspNetCore", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.AspNetCore.DataProtection", LogEventLevel.Information)
            .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .WriteTo.Console()
            .CreateLogger();

        builder.Host.UseSerilog();
        return builder;
    }

    /// <summary>
    /// Add keycloak as an external authentication provider. See:
    /// https://damienbod.com/2022/05/02/implement-an-openiddict-identity-provider-using-asp-net-core-identity-with-keycloak-federation/
    /// </summary>
    /// <param name="builder"></param>
    /// <returns></returns>
    public static AuthenticationBuilder AddKeyCloak(this AuthenticationBuilder builder)
    {
        // requires nuget: Microsoft.AspNetCore.Authentication.OpenIdConnect
        builder.AddOpenIdConnect("KeyCloak", "KeyCloak", options =>
        {
            options.SignInScheme = "Identity.External";
            //Keycloak server
            options.Authority = Startup.Settings.Configuration.GetSection("Keycloak")["ServerRealm"];
            //Keycloak client ID
            options.ClientId = Startup.Settings.Configuration.GetSection("Keycloak")["ClientId"];
            //Keycloak client secret in user secrets for dev
            options.ClientSecret = Startup.Settings.Configuration.GetSection("Keycloak")["ClientSecret"];
            //Keycloak .wellknown config origin to fetch config
            options.MetadataAddress = Startup.Settings.Configuration.GetSection("Keycloak")["Metadata"];
            //Require keycloak to use SSL

            options.GetClaimsFromUserInfoEndpoint = true;
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.SaveTokens = false;
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.RequireHttpsMetadata = false; //dev

            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = "name",
                RoleClaimType = ClaimTypes.Role,
                ValidateIssuer = true
            };
        });

        return builder;
    }
}
