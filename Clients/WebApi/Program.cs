using Microsoft.AspNetCore.Identity;
using OpenIddict.Validation.AspNetCore;
using Polly;
using WebApi.Models;
using WebApi.Policies;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.Configure<IdentityOptions>(options =>
{
    options.ClaimsIdentity.UserNameClaimType = OpenIddict.Abstractions.OpenIddictConstants.Claims.Email;
    options.ClaimsIdentity.UserIdClaimType = OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject;
    options.ClaimsIdentity.RoleClaimType = OpenIddict.Abstractions.OpenIddictConstants.Claims.Role;
});

builder.Services.AddAuthentication(options =>
        options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);

builder.Services
    .AddOpenIddict()
    .AddValidation(options =>
    {
        // Configure the validation handler to use introspection and register the client
        // credentials used when communicating with the remote introspection endpoint.
        options.UseIntrospection()
               .SetIssuer(builder.Configuration.GetValue<string>("oidc:Authority")!)
               .AddAudiences(builder.Configuration.GetValue<string>("oidc:Audience")!)
               .SetClientId(builder.Configuration.GetValue<string>("oidc:ClientId")!)
               .SetClientSecret(builder.Configuration.GetValue<string>("oidc:Secret")!);

        // Register the System.Net.Http integration.
        options.UseSystemNetHttp(config =>
            config.SetHttpErrorPolicy(HttpClientPolicies.GetRetryPolicy()
                .WrapAsync(HttpClientPolicies.GetCircuitBreakerPolicy())));

        // Register the ASP.NET Core host.
        options.UseAspNetCore();
    });

builder.Services.AddCors(options =>
    options.AddPolicy("CorsPolicy", policy =>
        policy.WithOrigins(builder.Configuration.GetSection("Cors:AllowedOrigins").Get<List<string>>()!.ToArray())
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials()));

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("Admin", policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
              .RequireRole("Admin"))
    .AddPolicy("User", policy =>
        policy.RequireAuthenticatedUser()
              .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
              .RequireRole("User"));

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseRouting();

app.UseCors("CorsPolicy");

app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
}).RequireAuthorization();

await app.RunAsync();
