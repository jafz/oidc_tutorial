using AuthorizationServer;

var builder = WebApplication.CreateBuilder(args);


var startup = new Startup(builder.Configuration);
startup.ConfigureServices(builder.Services);

var app = builder.Build();

//app.MapGet("/", () => "Hello World22!");
startup.Configure(app, builder.Environment);

app.Run();
