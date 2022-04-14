using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthorizationServer
{
    public class OpenIddictDbContext : DbContext
    {
        public OpenIddictDbContext(DbContextOptions<OpenIddictDbContext> options) : base(options)
        {

        }
    }
    public class DataProtectionContext : DbContext, IDataProtectionKeyContext
    {
        public DataProtectionContext(DbContextOptions<DataProtectionContext> options) : base(options)
        {

        }
        public DbSet<DataProtectionKey> DataProtectionKeys { get; set; }
    }
    public class Startup
    {
        public Startup(IConfigurationRoot configuration)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public IConfigurationRoot Configuration { get; }
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
                {
                    options.LoginPath = "/account/login";
                });

            services.AddDbContext<OpenIddictDbContext>(options =>
            {
                // Configure the context to use an in-memory store.
                //options.UseInMemoryDatabase(nameof(DbContext));
                options.UseSqlServer("Data Source=localhost;Initial Catalog=dev_30_auth;Integrated Security=True;MultipleActiveResultSets=True");

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });
            //services.AddDbContext<DataProtectionContext>(options =>
            //{
            //    options.UseSqlServer("Data Source=localhost;Initial Catalog=dev_30_auth;Integrated Security=True;MultipleActiveResultSets=True");
            //});

            //services.AddDataProtection()
            //    .PersistKeysToFileSystem(new DirectoryInfo(@"c:\dev\__delme\_dpapi_keys"))
            //    //.ProtectKeysWithCertificate(new System.Security.Cryptography.X509Certificates.X509Certificate2("path", "password"))
            //    // requires: Microsoft.AspNetCore.DataProtection.EntityFrameworkCore
            //    //.PersistKeysToDbContext<DataProtectionContext>()
            //    .SetApplicationName("Vinna")
            //    ;

            services.AddOpenIddict()
                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the EF Core stores/models.
                    options.UseEntityFrameworkCore()
                        .UseDbContext<OpenIddictDbContext>();
                })

                // Register the OpenIddict server components.
                .AddServer(options =>
                {
                    options.AllowClientCredentialsFlow();
                    // AllowAuthorizationCodeFlow enables the flow,
                    // RequireProofKeyForCodeExchange is called directly after that, this makes sure all clients are required to use PKCE (Proof Key for Code Exchange).
                    options
                        .AllowAuthorizationCodeFlow()
                        .RequireProofKeyForCodeExchange();
                    options
                        .AllowRefreshTokenFlow();

                    // The authorization code flow dictates that the user first authorizes the client to make requests in the user's behalf.
                    // Therefore, we need to implement an authorization endpoint which returns an authorization code to the client when the user allows it (/connect/authorize)
                    options
                        .SetAuthorizationEndpointUris("/connect/authorize")
                        .SetTokenEndpointUris("/connect/token")
                        .SetUserinfoEndpointUris("/connect/userinfo");

                    // introspection endpoint is created automatically. It only includes the claims iff:
                    //    - claims are in access token
                    //    - principal.SetResources("client id of app doing the introspection")
                    //    - api doing introspection is a confidential client (and forced to send a client_secret)
                    // https://stackoverflow.com/questions/64564559/how-to-get-introspect-to-return-information-such-as-email-with-openiddict
                    options
                        .SetIntrospectionEndpointUris("/connect/introspect");
                    ;

                    // when storing many claims - use reference (opaque) tokens
                    options
                        .UseReferenceAccessTokens()
                        .UseReferenceRefreshTokens();

                    // Encryption and signing of tokens
                    options
                        .AddEphemeralEncryptionKey()
                        .AddEphemeralSigningKey()
                        .DisableAccessTokenEncryption()
                        ;

                    // required for recognizing refresh tokens after restart
                    options.UseDataProtection();

                    // register scopes (permissions)
                    options.RegisterScopes("api");

                    // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                    // call EnableTokenEndpointPassthrough otherwise requests to our future token endpoint are blocked
                    options
                        .UseAspNetCore()
                        .EnableTokenEndpointPassthrough()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableUserinfoEndpointPassthrough()
                        ;
                })
            .AddValidation(options =>
            {
                // validation is used on resource services.

                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                options.UseIntrospection()
                   .SetClientId("resource_server_1")
                   .SetClientSecret("846B62D0-DEF9-4215-A99D-86E6B8DAB342");


                // Register the ASP.NET Core host.
                options.UseAspNetCore();
                options.UseDataProtection();
            })
                ;

            // Register the worker responsible of seeding the database with the sample clients.
            // Note: in a real world application, this step should be part of a setup script.
            services.AddHostedService<TestData>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // Uncomment the following lines to set up the DataProtection DB context
            //using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            //{
            //    var context = serviceScope.ServiceProvider.GetRequiredService<DataProtectionContext>();
            //    context.Database.Migrate();
            //}

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}