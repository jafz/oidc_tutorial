using Microsoft.AspNetCore.DataProtection;
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
        public UseCachedIntrospectionRequest(IDataProtectionProvider rootProvider)
        {
            _rootProvider = rootProvider;
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
                UseCachedIntrospectionRequest.Cache.TryAdd(token, context.Principal);
            }

            return default;
        }
    }
}
