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
