using AuthorizationServer;


var builder = WebApplication.CreateBuilder(args);

//builder.AddSerilog();
builder.AddSimpleConsoleLogging();

var startup = new Startup(builder.Configuration);
startup.ConfigureServices(builder.Services);

var app = builder.Build();

//app.MapGet("/", () => "Hello World22!");
startup.Configure(app, builder.Environment);

app.Run();
