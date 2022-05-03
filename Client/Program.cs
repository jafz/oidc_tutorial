using Client;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

Console.WriteLine("Press any key to start the authentication process.");
//Console.ReadKey();
Console.WriteLine("Joke. We autopressed it :)");

using var listener = new HttpListener();
listener.Prefixes.Add("http://localhost:8739/");
listener.Start();

string resourceUri1 = "https://localhost:7276/api";

var browser = new SystemBrowser();
var options = new OidcClientOptions
{
    Authority = "https://localhost:44369",
    ClientId = "console_app",
    LoadProfile = false,
    // if the redirect uri doesn't match 1:1 what is configured on the server (even a missing slash at the end), this fails with "invalid redirect uri"
    RedirectUri = "http://localhost:8739/",
    // RedirectUri = "http://localhost:8740/",
    // RedirectUri = "http://localhost:" + browser.Port + "/",
    Scope = "openid api1 api2",
    IdentityTokenValidator = new JwtHandlerIdentityTokenValidator(),
    // Browser = browser
};

var client2 = new HttpClient();
// var response = await client2.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
// {
//     Address = "https://localhost:44369/connect/token",

//     ClientId = "postman",
//     ClientSecret = "postman-secret",
//     Scope = "offline_access api openid api1 api2"
// });

// System.Console.WriteLine("response = " + response.Raw);

var client = new OidcClient(options);
var parameters = new IdentityModel.Client.Parameters(
    new Dictionary<string, string> { ["hardcoded_identity_id"] = "1" }
);

// var loginResult = await client.LoginAsync(new LoginRequest() { BrowserDisplayMode = IdentityModel.OidcClient.Browser.DisplayMode.Hidden });

var state = await client.PrepareLoginAsync(parameters);

Process.Start(new ProcessStartInfo { FileName = state.StartUrl, UseShellExecute = true });

// Wait for an authorization response to be posted to the local server
while (true)
{
    var context = await listener.GetContextAsync();
    context.Response.ContentType = "text/plain";
    context.Response.StatusCode = 200;


    var buffer = Encoding.UTF8.GetBytes("Login completed. Please return to the console app.");
    await context.Response.OutputStream.WriteAsync(buffer!);
    await context.Response.OutputStream.FlushAsync();

    context.Response.Close();

    var result = await client.ProcessResponseAsync(context.Request.Url.Query, state);

    if (result.IsError)
    {
        Console.WriteLine("An error occurred: {0}", result.Error);
    }
    else
    {
        // var at = response?.AccessToken ?? result.AccessToken;
        var at = result.AccessToken;
        Console.WriteLine("Response from Api1: {0}", await GetResourceFromApi1Async(at, resourceUri1));
        // test caching
        Console.WriteLine("Response from Api1: {0}", await GetResourceFromApi1Async(at, resourceUri1));
        Console.WriteLine("Response from Api1: {0}", await GetResourceFromApi1Async(at, resourceUri1));
        // Console.WriteLine("Response from Api2: {0}", await GetResourceFromApi2Async(result.AccessToken));
        break;
    }
}

Console.ReadLine();

static async Task<string> GetResourceFromApi1Async(string token, string resourceUri)
{
    using var client = new HttpClient();

    using var request = new HttpRequestMessage(HttpMethod.Get, resourceUri);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

    using var response = await client.SendAsync(request);
    if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
    {
        return "The user represented by the access token is not allowed to access Api1.";
    }

    response.EnsureSuccessStatusCode();

    return await response.Content.ReadAsStringAsync();
}

static async Task<string> GetResourceFromApi2Async(string token)
{
    using var client = new HttpClient();

    using var request = new HttpRequestMessage(HttpMethod.Get, "https://localhost:44379/api");
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

    using var response = await client.SendAsync(request);
    if (response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
    {
        return "The user represented by the access token is not allowed to access Api2.";
    }

    response.EnsureSuccessStatusCode();

    return await response.Content.ReadAsStringAsync();
}
