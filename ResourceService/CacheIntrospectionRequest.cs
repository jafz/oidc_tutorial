using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using OpenIddict.Validation;
using System.Collections.Concurrent;
using System.Security.Claims;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlerFilters;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers;

namespace ResourceService
{
    public static class Exts
    {
        public static OpenIddictValidationBuilder UseCaching(this OpenIddictValidationBuilder builder)
        {
            builder.AddEventHandler(CacheIntrospectionRequest.Descriptor);
            builder.AddEventHandler(UseCachedIntrospectionRequest.Descriptor);

            return builder;
        }
    }

    public class UseCachedIntrospectionRequest : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        public static ConcurrentDictionary<string, ClaimsPrincipal> Cache { get; private set; } = new ConcurrentDictionary<string, ClaimsPrincipal>();

        // The IDataProtectionProvider is registered by default in ASP.NET Core
        readonly IDataProtectionProvider _rootProvider;
        private readonly IDistributedCache _cache;

        public UseCachedIntrospectionRequest(IDataProtectionProvider rootProvider, IDistributedCache cache)
        {
            _rootProvider = rootProvider;
            _cache = cache;
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<UseCachedIntrospectionRequest>()
                .SetOrder(IntrospectToken.Descriptor.Order - 50)
                .SetType(OpenIddictValidationHandlerType.Custom)
                .Build();


        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            var token = context.Token;
            if (string.IsNullOrEmpty(token))
            {
                return default;
            }

            // we might want to protect the claimsprincipal that we store, in case the caching becomes an external cache where someone might be able to manipulate the tokens.
            //_rootProvider.CreateProtector("superman").Protect
            try
            {
                var item = _cache.Get(token);
                if (item is not null)
                {
                    var p = _rootProvider.CreateProtector("mega");
                    var pp = p.Unprotect(item);
                    var ms = new MemoryStream(pp);
                    var reader = new BinaryReader(ms);
                    var pr = new ClaimsPrincipal(reader);
                    context.Principal = pr;
                }
            }
            catch
            {

            }


            if (Cache.TryGetValue(token, out var principal))
            {
                context.Principal = principal;
                context.Logger.LogInformation("Retrieved principal from cache {principal}", principal);
            }

            return default;
        }
    }

    public class CacheIntrospectionRequest : IOpenIddictValidationHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
            = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                // only cache principals if we got them via introspection requests via api
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<CacheIntrospectionRequest>()
                .SetOrder(IntrospectToken.Descriptor.Order + 50)
                .SetType(OpenIddictValidationHandlerType.Custom)
                .Build();

        // The IDataProtectionProvider is registered by default in ASP.NET Core
        readonly IDataProtectionProvider _rootProvider;
        private readonly IDistributedCache _cache;

        public CacheIntrospectionRequest(IDataProtectionProvider rootProvider, IDistributedCache cache)
        {
            _rootProvider = rootProvider;
            _cache = cache;
        }

        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            var token = context.Token;
            if (string.IsNullOrEmpty(token))
            {
                return default;
            }

            if (context.Principal is not null)
            {
                try
                {
                    var p = _rootProvider.CreateProtector("mega");
                    var ms = new MemoryStream();
                    var writer = new BinaryWriter(ms);
                    context.Principal.WriteTo(writer);
                    // NOTE: this seems to lose data in the principal object...

                    byte[] principe = ms.ToArray();
                    var pp = p.Protect(principe);

                    _cache.Set(token, pp);
                }
                catch { }

                UseCachedIntrospectionRequest.Cache.TryAdd(token, context.Principal);
            }

            return default;
        }
    }
}
