using IdentitySuite;
using AdvancedConfiguration.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// overload to customize the IdentitySuiteOptions
builder.AddIdentitySuiteServices(options =>
{
    /* add one or more delegates to the endpoints you need to customize. 
     * The endpoints used in this example are a simplified version of the default ones used by the application, 
     * but they provide a complete example of the necessary configuration.
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
});

var app = builder.Build();

await app.SetupIdentitySuiteDbAsync();

app.UseIdentitySuiteServices();

await app.RunAsync();