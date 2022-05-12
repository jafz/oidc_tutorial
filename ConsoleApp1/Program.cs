using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddict.Validation;
using OpenIddict.Validation.SystemNetHttp;
using Polly;
using Polly.Extensions.Http;
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            var services = new ServiceCollection();
            //services.AddDistributedMemoryCache();

            //var id = WindowsIdentity.Impersonate()

            services.AddHttpClient();
            services.AddOpenIddict().AddValidation(options =>
            {
                // Note: the validation handler uses OpenID Connect discovery
                // to retrieve the address of the introspection endpoint
                options.SetIssuer("https://localhost:44369");
                options.AddAudiences("resource_server_1");

                options.UseIntrospection()
                    .SetClientId("resource_server_1")
                    .SetClientSecret("846B62D0-DEF9-4215-A99D-86E6B8DAB342");

                options.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(x =>
                {
                    x.SetOrder(int.MinValue);
                    x.UseInlineHandler(y =>
                    {
                        var r = y.Request;

                        return new ValueTask();
                    });
                });

                options.UseSystemNetHttp();
                options.UseOwin();
            });

            try
            {
                var pro = services.BuildServiceProvider();
                var _factory = pro.GetService<IHttpClientFactory>();

                var assembly = typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName();
                var client2 = _factory.CreateClient("memee");
                var ss = HttpPolicyExtensions.HandleTransientHttpError()
                    .OrResult(response => response.StatusCode == HttpStatusCode.NotFound)
                    .WaitAndRetryAsync(3, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)));

                var yso = new OpenIddictValidationSystemNetHttpOptions().HttpErrorPolicy;
                var client = _factory.CreateClient(assembly.Name);
                var a = client.GetAsync(new Uri("https://localhost:44369/.well-known/openid-configuration")).Result;

                var cfg = new OpenIdConnectConfiguration
                {
                    Issuer = "https://localhost:44369",
                };

                var xx = new StaticConfigurationManager<OpenIdConnectConfiguration>(cfg);
                var yo = xx.GetConfigurationAsync(CancellationToken.None).Result;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

        }
    }
}
