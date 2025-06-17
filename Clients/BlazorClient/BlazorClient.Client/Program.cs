using BlazorClient.Client.Services;
using BlazorClient.Shared;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

var builder = WebAssemblyHostBuilder.CreateDefault(args);

builder.Services.AddAuthorizationCore();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthenticationStateDeserialization();

builder.Services.AddHttpClient("WebApiClient", client =>
{
    client.BaseAddress = new Uri("https://localhost:5010/");
});

builder.Services.AddScoped<IWeatherService, WeatherServiceClient>(sp =>
    new WeatherServiceClient(
        sp.GetRequiredService<IHttpClientFactory>().CreateClient("WebApiClient")));

await builder.Build().RunAsync();
