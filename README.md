[![IdentitySuite](https://img.shields.io/nuget/v/IdentitySuite.svg?style=plastic)](https://nuget.org/packages/IdentitySuite)

# IdentitySuite Demo Projects

This repository contains two demo projects that demonstrate how to configure the **IdentitySuite** library in different scenarios. There is also a **Clients** section where you can find configuration examples of some types of clients.

## Repository Structure

1. **BasicConfiguration**: Minimum configuration required to get IdentitySuite up and running.
2. **AdvancedConfiguration**: Advanced example with customization of OpenIddict endpoints.
3. **Clients**: Some projects with minimal configuration to play with:
   - **BlazorClient**: Blazor web application
   - More to come

## BasicConfiguration

The project in the `BasicConfiguration` folder shows the essential configuration to integrate IdentitySuite into your project.

### Configuration
1. Configure your database by editing the connection string in: `/IdentitySuite/identitySuiteSettings.Development.json`
2. Run `dotnet restore`
3. Start the project with `dotnet run`

## AdvancedConfiguration

The project in the `AdvancedConfiguration` folder demonstrates how to customize OpenIddict endpoints to meet your specific needs.

### Demonstrated Features
- Customize Authorization Endpoints
- Configure Custom Tokens
- Advanced Scope Management

### Configuration
1. Configure your database by editing the connection string in: `/IdentitySuite/identitySuiteSettings.Development.json`
2. Run `dotnet restore`
3. Start the project with `dotnet run`


## Clients

### Blazor Client Configuration

To configure the Blazor client in **IdentitySuite**, follow these steps:

1. **Navigate to Applications Menu**  
   Go to *Clients/Resources* → *Applications* in the IdentitySuite dashboard.

2. **Create a New Application**  
   - Click **Add**
   - Select **Single Page Application** as the application type
   - Enter `blazor-client` as the *Client Id*

3. **Configure Application URLs**  
   Under *Application Urls*, add the following:
   - **Redirect URIs**:  
     `https://localhost:5010/signin-oidc`
   - **Post Logout Redirect URIs**:  
     `https://localhost:5010/signout-callback-oidc`

4. **Save Changes**  
   Click the **Save** button to apply your configuration.


## Support

For issues or questions, open an [issue](https://github.com/spin973/IdentitySuite/issues) on GitHub.
