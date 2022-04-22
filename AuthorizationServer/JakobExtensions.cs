using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using Serilog;
using Serilog.Events;

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
}

public class Mana<TApplication> : OpenIddictApplicationManager<TApplication> where TApplication : class
{
    public Mana(IOpenIddictApplicationCache<TApplication> cache, ILogger<OpenIddictApplicationManager<TApplication>> logger, IOptionsMonitor<OpenIddictCoreOptions> options, IOpenIddictApplicationStoreResolver resolver) : base(cache, logger, options, resolver)
    {
    }

    public override async ValueTask<bool> ValidateRedirectUriAsync(
    TApplication application, string address, CancellationToken cancellationToken = default)
    {
        var baseResult = await base.ValidateRedirectUriAsync(application, address, cancellationToken);
        if (baseResult)
            return true;

        if (address.StartsWith("http://[::1]")
            || address.StartsWith("http://localhost")
            || address.StartsWith("http://127.0.0.1")
            )
        {
            foreach (var uri in await Store.GetRedirectUrisAsync(application, cancellationToken))
            {
                // Note: https://datatracker.ietf.org/doc/html/rfc8252#section-7.3
                // 7.3.  Loopback Interface Redirection
                // The authorization server MUST allow any port to be specified at the
                // time of the request for loopback IP redirect URIs, to accommodate
                // clients that obtain an available ephemeral port from the operating
                // system at the time of the request.
                if (uri.StartsWith("http://[::1]")
                || uri.StartsWith("http://localhost")
                || uri.StartsWith("http://127.0.0.1")
                    )

                    return true;
            }

        }

        return false;
    }
}
