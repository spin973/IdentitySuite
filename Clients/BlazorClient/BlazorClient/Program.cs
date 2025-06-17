using BlazorClient.Authentication;
using BlazorClient.Client.Services;
using BlazorClient.Components;
using BlazorClient.Services;
using BlazorClient.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents()
    .AddInteractiveWebAssemblyComponents()
    .AddAuthenticationStateSerialization(options => options.SerializeAllClaims = true);

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.Authority = "https://localhost:5000/";
    options.ClientId = "blazor-client";

    options.Scope.Add("email");
    options.Scope.Add("profile");
    options.Scope.Add("roles");
    options.Scope.Add("Public.Webapi");

    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;
    options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;
    options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.UseIfAvailable;
    options.TokenValidationParameters.NameClaimType = ClaimTypes.NameIdentifier;
    options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.MapInboundClaims = true;
    options.ClaimActions.MapAll();

    //options.Events.OnRedirectToIdentityProvider = context =>
    //{
    //    //use this to pass a specific culture to identity server
    //    context.ProtocolMessage.SetParameter("ui_locales", CultureInfo.CurrentCulture.Name);
    //    return Task.CompletedTask;
    //};
    options.Events.OnSignedOutCallbackRedirect = async context =>
    {
        // Sign out from local cookie
        await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        // Redirect to landing page
        context.Response.Redirect(context.Options.SignedOutRedirectUri);
        context.HandleResponse();
    };
})
.AddCookie(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.LoginPath = new PathString("/Authentication/LogIn");
    options.LogoutPath = new PathString("/Authentication/LogOut");
});

builder.Services.ConfigureCookieOidc(CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddControllers();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<TokenHandler>();

builder.Services.AddScoped<IWeatherService, WeatherServiceServer>();

builder.Services.AddHttpClient("WebApiClient", client =>
{
    client.BaseAddress = new Uri("https://localhost:5002/");
}).AddHttpMessageHandler<TokenHandler>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapControllers();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(BlazorClient.Client._Imports).Assembly);

app.Run();
