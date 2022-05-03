using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Core;

public class OpenIddictAppManagerCustom<TApplication> : OpenIddictApplicationManager<TApplication> where TApplication : class
{
    public OpenIddictAppManagerCustom(IOpenIddictApplicationCache<TApplication> cache, ILogger<OpenIddictApplicationManager<TApplication>> logger, IOptionsMonitor<OpenIddictCoreOptions> options, IOpenIddictApplicationStoreResolver resolver) : base(cache, logger, options, resolver)
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
