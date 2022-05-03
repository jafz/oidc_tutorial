using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthorizationServer
{
    public class TestData : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public TestData(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<OpenIddictDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var postman = await manager.FindByClientIdAsync("postman", cancellationToken);
            if (postman is OpenIddictEntityFrameworkCoreApplication d)
            {
                if (d.Permissions.Contains(Permissions.Prefixes.Scope + "unattended") == false
                    || d.Permissions.Contains(Permissions.Prefixes.Scope + "interactive") == false
                   )
                {
                    await manager.DeleteAsync(postman, cancellationToken);
                    postman = null;
                }
            }
            if (postman is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "postman",
                    ClientSecret = "postman-secret",
                    DisplayName = "Postman",
                    RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback"), new Uri("http://postman") },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Introspection,

                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.GrantTypes.RefreshToken,

                        Permissions.Prefixes.Scope + "api",
                        Permissions.Prefixes.Scope + "unattended",
                        Permissions.Prefixes.Scope + "interactive",

                        Permissions.ResponseTypes.Code,
                    }
                }, cancellationToken);
            }

            var findByClientIdAsync = await manager.FindByClientIdAsync("postman2", cancellationToken);

            if (findByClientIdAsync is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "postman2",
                    ClientSecret = "postman-secret",
                    DisplayName = "Postman",
                    RedirectUris = { new Uri("https://oauth.pstmn.io/v1/callback"), new Uri("http://postman") },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Introspection,

                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.GrantTypes.RefreshToken,

                        Permissions.Prefixes.Scope + "api",
                        Permissions.Prefixes.Scope + "api1",
                        Permissions.Prefixes.Scope + "api2",

                        Permissions.ResponseTypes.Code,
                    }
                }, cancellationToken);
            }

            var byClientIdAsync = await manager.FindByClientIdAsync("insomnia", cancellationToken);
            if (byClientIdAsync is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "insomnia",
                    //ClientSecret = "insomnia-secret",
                    DisplayName = "Insomnia",
                    RedirectUris = { new Uri("http://insomnia"), new Uri("https://www.google.com") },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Introspection,

                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.ClientCredentials,
                        Permissions.GrantTypes.RefreshToken,

                        Permissions.Prefixes.Scope + "api",

                        Permissions.ResponseTypes.Code,
                    }
                }, cancellationToken);
            }
            if (await manager.FindByClientIdAsync("console_app") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "console_app",
                    RedirectUris =
                {
                    new Uri("http://localhost:8739/")
                },
                    Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + "api1",
                    Permissions.Prefixes.Scope + "api2"
                }
                });
            }

            if (await manager.FindByClientIdAsync("resource_server_1") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientId = "resource_server_1",
                    ClientSecret = "846B62D0-DEF9-4215-A99D-86E6B8DAB342",
                    Permissions =
                {
                    Permissions.Endpoints.Introspection
                }
                });
            }

            await CreateScopesAsync(scope);
        }

        async Task CreateScopesAsync(IServiceScope scope)
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            if (await manager.FindByNameAsync("api1") is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "api1",
                    Resources =
                {
                    "resource_server_1"
                }
                });
            }

            if (await manager.FindByNameAsync("api2") is null)
            {
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = "api2",
                    Resources =
                {
                    "resource_server_2"
                }
                });
            }
        }


        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
