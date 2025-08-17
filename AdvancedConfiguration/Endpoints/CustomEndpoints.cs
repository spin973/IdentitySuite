using IdentitySuite.Core.Data.Entities;
using IdentitySuite.Core.Extensions;
using IdentitySuite.Core.Models.Endpoints;
using IdentitySuite.Core.Services.Interfaces;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AdvancedConfiguration.Endpoints;

public static class CustomEndpoints
{
    public static async Task<IResult> AuthorizeEndpointDelegate(
        HttpContext httpContext,
        HttpRequest httpRequest,
        UserManager<IdentityUserEntity> userManager,
        ISessionClientDataService sessionClientData,
        IOpenIddictScopeManager scopeManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOptions<RequestLocalizationOptions> localizationOptions,
        ILogger logger)
    {
        var request = httpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!string.IsNullOrEmpty(request.UiLocales))
        {
            var culture = new CultureInfo(request.UiLocales);
            var supportedCultures = localizationOptions.Value.SupportedUICultures
                ?.Select(cultureInfo => cultureInfo.Name).ToList();
            if (supportedCultures?.Contains(culture.Name) == true)
            {
                CultureInfo.CurrentCulture = culture;
                CultureInfo.CurrentUICulture = culture;

                var requestCulture = new RequestCulture(culture);

                httpContext.Response.Cookies.Append(
                    CookieRequestCultureProvider.DefaultCookieName,
                    CookieRequestCultureProvider.MakeCookieValue(requestCulture),
                    new CookieOptions
                    {
                        Expires = DateTimeOffset.UtcNow.AddYears(1),
                        IsEssential = true,
                        Path = "/",
                        HttpOnly = true,
                    }
                );
            }
            else
            {
                logger.LogWarning("The specified culture is not supported: {Culture}", culture.Name);
            }
        }

        var result = await httpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!result.Succeeded)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Collects data about the client application for use in login pages.
            // The first time the user logs in, the data is stored in the session,
            // further times, the data is retrieved from the session.
            await sessionClientData.GetClientDataAsync(request.ClientId, request.RedirectUri);

            return Results.Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = httpRequest.PathBase + httpRequest.Path + QueryString.Create(
                        httpRequest.HasFormContentType ? httpRequest.Form.ToList() : httpRequest.Query.ToList())
                },
                authenticationSchemes: [IdentityConstants.ApplicationScheme]);
        }

        if (request.HasPromptValue(PromptValues.Login))
        {
            var prompt = string.Join(" ", request.GetPromptValues().Remove(PromptValues.Login));

            var parameters = httpRequest.HasFormContentType
                ? httpRequest.Form.Where(parameter => parameter.Key != Parameters.Prompt).ToList()
                : httpRequest.Query.Where(parameter => parameter.Key != Parameters.Prompt).ToList();

            parameters.Add(KeyValuePair.Create(Parameters.Prompt, new StringValues(prompt)));

            return Results.Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = httpRequest.PathBase + httpRequest.Path + QueryString.Create(parameters)
                },
                authenticationSchemes: [IdentityConstants.ApplicationScheme]);
        }

        if (request.MaxAge != null &&
            result.Properties?.IssuedUtc != null &&
            DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value))
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            return Results.Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = httpRequest.PathBase + httpRequest.Path + QueryString.Create(
                        httpRequest.HasFormContentType ? httpRequest.Form.ToList() : httpRequest.Query.ToList())
                },
                authenticationSchemes: [IdentityConstants.ApplicationScheme]);
        }

        var user = await userManager.GetUserAsync(result.Principal ?? new ClaimsPrincipal());
        if (user is null)
        {
            return Results.Forbid(
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user does not exist."
                }),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var clientApplication = await sessionClientData.GetClientDataAsync(request.ClientId, request.RedirectUri);
        if (clientApplication is null)
        {
            return Results.Forbid(
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "Details concerning the calling client application cannot be found."
                }),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var authorizations = await authorizationManager.FindAsync(
            subject: await userManager.GetUserIdAsync(user),
            client: clientApplication.Id,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        switch (clientApplication.ConsentType)
        {
            case ConsentTypes.External when authorizations.Count == 0:
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Count > 0:
            case ConsentTypes.Explicit when authorizations.Count > 0 && !request.HasPromptValue(PromptValues.Consent):
                var principal = result.Principal!;

                principal.SetScopes(request.GetScopes());
                principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

                var authorization = authorizations.LastOrDefault();

                authorization ??= await authorizationManager.CreateAsync(
                    principal: principal,
                    subject: await userManager.GetUserIdAsync(user),
                    client: clientApplication.Id,
                    type: AuthorizationTypes.Permanent,
                    scopes: principal.GetScopes());

                principal.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));

                foreach (var claim in principal.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim, principal));
                }

                return Results.SignIn(principal,
                    authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            case ConsentTypes.Explicit when request.HasPromptValue(PromptValues.None):
            case ConsentTypes.Systematic when request.HasPromptValue(PromptValues.None):
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

            default:
                return Results.LocalRedirect(
                    $"/Account/Consent{httpContext.Request.QueryString}&clientId={clientApplication.ClientId}&scope={request.Scope}");
        }
    }

    public static async Task<IResult> ConsentEndpointDelegate(
        HttpContext httpContext,
        HttpRequest httpRequest,
        UserManager<IdentityUserEntity> userManager,
        SignInManager<IdentityUserEntity> signInManager,
        IOpenIddictScopeManager scopeManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        ILogger logger)
    {
        var submitAction = httpRequest.Form["submit.Accept"].FirstOrDefault();
        var submitDeny = httpRequest.Form["submit.Deny"].FirstOrDefault();

        var request = httpContext.GetOpenIddictServerRequest() ?? 
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the profile of the logged-in user.
        var user = await userManager.GetUserAsync(httpContext.User) ?? 
                   throw new InvalidOperationException("The user details cannot be retrieved.");

        if (!string.IsNullOrEmpty(submitDeny) || string.IsNullOrEmpty(submitAction))
        {
            logger.LogInformation("User {User} has rejected consent.", user.Id);
            
            return Results.Forbid(
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The user has not agreed to the consent."
                }),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }
        
        // Retrieve the application details from the database.
        var application = await applicationManager.FindByClientIdAsync(request.ClientId ?? string.Empty) ?? 
                          throw new InvalidOperationException(
                              "Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await authorizationManager.FindAsync(
            subject: await userManager.GetUserIdAsync(user),
            client: await applicationManager.GetIdAsync(application) ?? string.Empty,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()).ToListAsync();

        // Note: the same check is already made in the other action but is repeated
        // here to ensure a malicious user can't abuse this POST-only endpoint and
        // force it to return a valid response without the external authorization.
        if (authorizations.Count == 0 &&
            await applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
        {
            return Results.Forbid(
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                }),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var principal = await signInManager.CreateUserPrincipalAsync(user);

        // Note: in this sample, the granted scopes match the requested scope, 
        // but you may want to allow the user to uncheck specific scopes.
        // For that, restrict the list of scopes before calling SetScopes.
        principal.SetScopes(request.GetScopes());
        principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        var authorization = authorizations.LastOrDefault();

        authorization ??= await authorizationManager.CreateAsync(
            principal: principal,
            subject: await userManager.GetUserIdAsync(user),
            client: await applicationManager.GetIdAsync(application) ?? string.Empty,
            type: AuthorizationTypes.Permanent,
            scopes: principal.GetScopes());

        principal.SetAuthorizationId(await authorizationManager.GetIdAsync(authorization));

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }
        
        logger.LogInformation("User {User} has granted consent.", user.Id);
        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    public static async Task<IResult> UserInfoEndpointDelegate(
        HttpContext httpContext,
        UserManager<IdentityUserEntity> userManager,
        ILogger logger)
    {
        var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = result.Principal;

        if (principal is null)
        {
            return Results.Forbid(
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The access token was rejected."
                }),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var user = await userManager.GetUserAsync(principal);
        if (user is null)
        {
            return Results.Forbid(
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                        "The specified access token is bound to an account that no longer exists."
                }),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var userClaims = await userManager.GetClaimsAsync(user);

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            [Claims.Subject] = await userManager.GetUserIdAsync(user)
        };

        if (user.FirstName != null)
        {
            claims[Claims.GivenName] = user.FirstName;
        }

        if (user.LastName != null)
        {
            claims[Claims.FamilyName] = user.LastName;
        }

        if (user is { FirstName: not null, LastName: not null })
        {
            claims[Claims.Name] = $"{user.FirstName} {user.LastName}";
        }

        if (principal.HasScope(Scopes.Address))
        {
            claims[Claims.Address] = JsonSerializer.Serialize(new
            {
                street_address = userClaims.FirstOrDefault(p => p.Issuer == ClaimTypes.StreetAddress),
                locality = userClaims.FirstOrDefault(p => p.Issuer == ClaimTypes.Locality),
                postal_code = userClaims.FirstOrDefault(p => p.Issuer == ClaimTypes.PostalCode),
                country = userClaims.FirstOrDefault(p => p.Issuer == ClaimTypes.Country)
            });
        }

        if (principal.HasScope(Scopes.Phone))
        {
            claims[Claims.PhoneNumber] = await userManager.GetPhoneNumberAsync(user) ?? string.Empty;
        }

        if (principal.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = await userManager.GetEmailAsync(user) ?? string.Empty;
        }

        if (principal.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await userManager.GetRolesAsync(user);
        }

        logger.LogInformation("User Id {UserId} is authenticated.", user.Id);
        // Note: the complete list of standard claims supported by the OpenID Connect specification
        // can be found here: http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        return Results.Ok(claims);
    }

    public static async Task<IResult> TokenEndpointDelegate(
        HttpContext httpContext,
        UserManager<IdentityUserEntity> userManager,
        SignInManager<IdentityUserEntity> signInManager,
        IOpenIddictScopeManager scopeManager,
        IOpenIddictApplicationManager applicationManager,
        ILogger logger)
    {
        var request = httpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsPasswordGrantType())
        {
            var user = await userManager.FindByNameAsync(request.Username ?? string.Empty);
            if (user == null || !await userManager.CheckPasswordAsync(user, request.Password ?? string.Empty))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Invalid username or password."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Ensure the user is allowed to sign in
            if (!await signInManager.CanSignInAsync(user))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user is no longer allowed to sign in."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Create the claims-based identity
            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Add the claims that will be persisted in the tokens
            identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
                .SetClaims(Claims.Role, [.. await userManager.GetRolesAsync(user)]);

            ClaimsPrincipal principal = new(identity);
            // Set scopes (you might want to validate requested scopes)
            principal.SetScopes(request.GetScopes());
            principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

            // Set destinations for claims
            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return Results.SignIn(
                principal,
                authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the authorization code/device code/refresh token.
            var principal =
                (await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
                .Principal;

            // Retrieve the user profile corresponding to the authorization code/refresh token.
            // Note: if you want to automatically invalidate the authorization code/refresh token
            // when the user password/roles change, use the following line instead:
            //// var user = _signInManager.ValidateSecurityStampAsync(info.Principal);
            var user = await userManager.GetUserAsync(principal ?? new ClaimsPrincipal());
            if (user == null)
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The token is no longer valid."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Ensure the user is still allowed to sign in.
            if (!await signInManager.CanSignInAsync(user))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user is no longer allowed to sign in."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            if (principal is not null)
            {
                foreach (var claim in principal.Claims)
                {
                    claim.SetDestinations(GetDestinations(claim, principal));
                }

                principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

                // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
                return Results.SignIn(principal,
                    authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }
        }
        else if (request.IsClientCredentialsGrantType())
        {
            var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Client authentication failed."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Note: the client credentials are automatically validated by OpenIddict:
            // if client_id or client_secret are invalid, this action won't be invoked.

            //However, OpenIddict does NOT validate the Scopes are valid, so we need to do that here.
            if (!await scopeManager.ScopesExist(request))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidScope,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The specified scopes are not valid."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            var application = await applicationManager.FindByClientIdAsync(request.ClientId ?? string.Empty);
            if (application == null)
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Client not found."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Subject (sub) is a required field, we use the client id as the subject identifier here.
            identity.SetClaim(Claims.Subject, await applicationManager.GetClientIdAsync(application));
            identity.SetClaim(Claims.Name, await applicationManager.GetDisplayNameAsync(application));

            // Add Claims Applied to Client
            foreach (var (type, values) in await applicationManager.GetClaimValuesDictionary(application))
            {
                identity.AddClaims(type, values);
            }

            ClaimsPrincipal principal = new(identity);

            principal.SetScopes(request.GetScopes());
            principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return Results.SignIn(
                principal,
                properties: null,
                authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        else if (request.IsDeviceCodeGrantType())
        {
            // Retrieve the claims principal stored in the device code
            var principal =
                (await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme))
                .Principal;

            if (principal == null)
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The device code is not valid or has expired."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Retrieve the user profile corresponding to the device code
            var user = await userManager.GetUserAsync(principal);
            if (user == null)
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The device code is not associated with a valid user."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            // Ensure the user is still allowed to sign in
            if (!await signInManager.CanSignInAsync(user))
            {
                return Results.Forbid(
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user is no longer allowed to sign in."
                    }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

            return Results.SignIn(principal,
                authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Results.Forbid(
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                    "The specified grant is not supported."
            }),
            authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    public static async Task<IResult> LogoutGetEndpointDelegate(
        HttpContext httpContext,
        ISessionClientDataService sessionClientData,
        IOpenIddictApplicationManager applicationManager,
        ILogger logger)
    {
        var request = httpContext.GetOpenIddictServerRequest();

        if (request?.PostLogoutRedirectUri is null)
        {
            return Results.LocalRedirect("/Account/Logout");
        }

        var applications = await applicationManager.FindByPostLogoutRedirectUriAsync(request.PostLogoutRedirectUri)
            .ToListAsync();

        if (applications.FirstOrDefault() is { } application)
        {
            request.ClientId = await applicationManager.GetClientIdAsync(application);

            await sessionClientData.GetClientDataAsync(request.ClientId);
        }

        return Results.LocalRedirect($"/Account/Logout{httpContext.Request.QueryString}");
    }

    public static async Task<IResult> LogoutPostEndpointDelegate(
        [FromForm] IFormCollection parameters,
        SignInManager<IdentityUserEntity> signInManager,
        ILogger logger)
    {
        // Ask ASP.NET Core Identity to delete the local and external cookies created
        // when the user agent is redirected from the external identity provider
        // after a successful authentication flow (e.g., Google or Facebook).
        await signInManager.SignOutAsync();

        // Returning a SignOutResult will ask OpenIddict to redirect the user agent
        // to the post_logout_redirect_uri specified by the client application or to
        // the RedirectUri specified in the authentication properties if none was set.
        return Results.SignOut(
            properties: new AuthenticationProperties { RedirectUri = "/" },
            authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    public static async Task<IResult> VerifyGetEndpointDelegate(
        HttpContext httpContext,
        IOpenIddictApplicationManager applicationManager,
        ILogger logger)
    {
        var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        if (result is { Succeeded: true } && !string.IsNullOrEmpty(result.Principal.GetClaim(Claims.ClientId)))
        {
            var application =
                await applicationManager.FindByClientIdAsync(result.Principal.GetClaim(Claims.ClientId)!) ??
                throw new InvalidOperationException(
                    "Details concerning the calling client application cannot be found.");

            var clientId = await applicationManager.GetClientIdAsync(application);
            var scope = string.Join(" ", result.Principal.GetScopes());
            var userCode = result.Properties!.GetTokenValue(OpenIddictServerAspNetCoreConstants.Tokens.UserCode);

            return Results.LocalRedirect($"/Account/Verify?user_code={userCode}&clientId={clientId}&scope={scope}");
        }
        else if (!string.IsNullOrEmpty(result.Properties!.GetTokenValue(OpenIddictServerAspNetCoreConstants.Tokens.UserCode)))
        {
            const string error = Errors.InvalidToken;
            const string errorDescription =
                "The specified user code is not valid. Please make sure you typed it correctly.";

            return Results.LocalRedirect($"/Account/Verify?error={error}&error_description={errorDescription}");
        }

        return Results.LocalRedirect($"/Account/Verify");
    }

    public static async Task<IResult> VerifyPostEndpointDelegate(
        HttpContext httpContext,
        HttpRequest httpRequest,
        UserManager<IdentityUserEntity> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        ILogger logger)
    {
        var submitAction = httpRequest.Form["submit.Accept"].FirstOrDefault();
        var submitDeny = httpRequest.Form["submit.Deny"].FirstOrDefault();

        if (!string.IsNullOrEmpty(submitDeny) || string.IsNullOrEmpty(submitAction))
        {
            return Results.Forbid(
                properties: new AuthenticationProperties
                {
                    // This property points to the address OpenIddict will automatically
                    // redirect the user to after rejecting the authorization demand.
                    RedirectUri = "/"
                },
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var request = httpContext.GetOpenIddictServerRequest();
        if (request == null)
        {
            return Results.BadRequest("Invalid request.");
        }

        var result = await httpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!result.Succeeded)
        {
            return Results.Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = httpRequest.PathBase + httpRequest.Path + httpRequest.QueryString
                },
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var user = await userManager.GetUserAsync(httpContext.User);
        if (user == null)
        {
            return Results.Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = httpRequest.PathBase + httpRequest.Path + httpRequest.QueryString
                },
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Add the claims that will be persisted in the tokens.
        identity.SetClaim(Claims.Subject, await userManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email, await userManager.GetEmailAsync(user))
            .SetClaim(Claims.Name, await userManager.GetUserNameAsync(user))
            .SetClaim(Claims.PreferredUsername, await userManager.GetUserNameAsync(user))
            .SetClaims(Claims.Role, [.. (await userManager.GetRolesAsync(user))]);

        ClaimsPrincipal principal = new(identity);

        // Note: in this sample, the granted scopes match the requested scope, but
        // you may want to allow the user to uncheck specific scopes.
        // For that, restrict the list of scopes before calling SetScopes.
        principal.SetScopes(request.GetScopes());
        principal.SetResources(await scopeManager.ListResourcesAsync(principal.GetScopes()).ToListAsync());

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        var properties = new AuthenticationProperties
        {
            // This property points to the address OpenIddict will automatically
            // redirect the user to after validating the authorization demand.
            RedirectUri = "/"
        };

        logger.LogInformation("Device verification completed for user {UserId}", user.Id);

        return Results.SignIn(principal, properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        switch (claim.Type)
        {
            case Claims.Name:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Profile))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;
            
            case Claims.Email:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Email))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;
            
            case Claims.Role:
                yield return Destinations.AccessToken;
                if (principal.HasScope(Scopes.Roles))
                {
                    yield return Destinations.IdentityToken;
                }
                yield break;
            
            case "AspNet.Identity.SecurityStamp": yield break;
            
            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
