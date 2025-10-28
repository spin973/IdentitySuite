using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = new PathString("/login");
        options.LogoutPath = new PathString("/logout");
        options.Cookie.Name = CookieAuthenticationDefaults.CookiePrefix + CookieAuthenticationDefaults.AuthenticationScheme;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(50);
        options.SlidingExpiration = false;
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = "https://localhost:5000";
        options.ClientId = "mvc-client";
        options.ClientSecret="P9gXukEbOIAG1hIU9saNJUnNjU9xvVUC";
        options.GetClaimsFromUserInfoEndpoint = true;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;
        options.UsePkce = true;
        options.Scope.Add("email");
        options.Scope.Add("profile");
        options.Scope.Add("roles");
        options.Scope.Add("Public.Webapi");
        options.SaveTokens = true;

        options.UseSecurityTokenValidator = true;

        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "role";
        options.GetClaimsFromUserInfoEndpoint = true;
        options.MapInboundClaims = false;

        options.AccessDeniedPath = "/";
    });

builder.Services.AddHttpClient();

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();


app.Run();
