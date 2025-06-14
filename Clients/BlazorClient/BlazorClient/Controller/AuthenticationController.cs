namespace BlazorClient.Controller;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Specialized;

[Route("[controller]/[action]")]
public class AuthenticationController : Controller
{
    [HttpGet]
    public ActionResult LogIn([FromQuery] string returnUrl)
    {
        return Challenge(new AuthenticationProperties { RedirectUri = returnUrl ?? "/" }, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet, HttpPost]
    [Authorize]
    public ActionResult LogOut()
    {
        // Instruct the cookies middleware to delete the local cookie created when the user agent
        // is redirected from the identity provider after a successful authorization flow and
        // to redirect the user agent to the identity provider to sign out.
        return SignOut(new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet, HttpPost]
    [Authorize]
    public ActionResult Manage([FromQuery] string returnUrl)
    {
        var clientId = "blazor-client";
        var authority = "https://localhost:5000/";
        var uriBuilder = new UriBuilder(authority!)
        {
            Path = "/Account/Manage"
        };
        NameValueCollection querystring = System.Web.HttpUtility.ParseQueryString(string.Empty);
        querystring.Add("clientid", clientId);
        querystring.Add("returnurl", returnUrl);
        uriBuilder.Query = querystring.ToString();

        var url = uriBuilder.ToString();

        return Redirect(url);
    }
}