using Serilog;
using IdentitySuite;
using AdvancedConfiguration.Endpoints;

try
{
    var builder = WebApplication.CreateBuilder(args);

    ConfigureLogging(builder);
    var loggerFactory = LoggerFactory.Create(builder => builder.AddSerilog(Log.Logger));
    var logger = loggerFactory.CreateLogger<Program>();

    logger.LogInformation("Starting Web Host...");

    // overload to customize the IdentitySuiteOptions
    builder.AddIdentitySuiteServices(options =>
    {
        /* add one or more delegates to the endpoints you need to customize. 
         * The endpoints used in this example are the default ones used by the application, 
         * to have a complete example of the necessary configuration. 
         * Please note that the properties you set in 'options' override the settings managed in the configuration menu
         * and therefore those parameters will not be operational. */
        options.OpenIddictOptions.ServerEndpointOptions = new()
        {
            AuthorizeEndpoint = CustomEndpoints.AuthorizeEndpointDelegate,
            ConsentEndpoint = CustomEndpoints.ConsentEndpointDelegate,
            UserInfoEndpoint = CustomEndpoints.UserInfoEndpointDelegate,
            TokenEndpoint = CustomEndpoints.TokenEndpointDelegate,
            LogoutGetEndpoint = CustomEndpoints.LogoutGetEndpointDelegate,
            LogoutPostEndpoint = CustomEndpoints.LogoutPostEndpointDelegate
        };
    }, logger);

    var app = builder.Build();

    await app.SetupIdentitySuiteDbAsync(logger);

    app.UseIdentitySuiteServices(logger);

    await app.RunAsync();

    logger.LogInformation("Web Host terminated regularly.");
}
catch (Exception ex)
{
    Log.Fatal(ex, "Web Host terminated unexpectedly.");
}
finally
{
    Log.Information("Web Host Shutdown.");
    await Log.CloseAndFlushAsync();
}

static void ConfigureLogging(WebApplicationBuilder builder)
{
    Log.Logger = new LoggerConfiguration()
        .ReadFrom.Configuration(builder.Configuration)
        .CreateLogger();

    builder.Logging
        .ClearProviders()
        .AddSerilog();
}
