[![IdentitySuite](https://img.shields.io/nuget/v/IdentitySuite.svg?style=plastic)](https://nuget.org/packages/IdentitySuite)

# IdentitySuite Demo Projects

This repository contains two demo projects that demonstrate how to configure the **IdentitySuite** library in different scenarios. There is also a **Clients** section where you can find configuration examples of some types of clients.

## Repository Structure

- **BasicConfiguration**: Minimum configuration required to get IdentitySuite up and running.
- **AdvancedConfiguration**: Advanced example with customization of OpenIddict endpoints.
- **Clients**: Some projects with minimal configuration to play with:
  - **BlazorClient**: Blazor web application, Authorization code flow + PKCE, use access tokens for the Web API
  - **MvcClient**: ASP.NET Core MVC web application, a server-side application using OpenID Connect, use access tokens for the Web API
  - **ClientCredentialFlow**: Console application, a client using the Client Credentials flow, request access tokens for the Web API
  - **ResourceOwnerFlow**: Console application, a client using the Resource Owner Password Credentials flow, request access tokens for the Web API
  - **DeviceAuthorizationFlow**: Console application, a client using the Device Authorization flow, request access tokens for the Web API
  - **WebApi**: ASP.NET Core Web API application, a resource using introspection to validate tokens
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

### Configuration
1. Configure your database by editing the connection string in: `/IdentitySuite/identitySuiteSettings.Development.json`
2. Run `dotnet restore`
3. Start the project with `dotnet run`


## Using Clients

You can use the clients in the `Client` folder to test the IdentitySuite server. Each client has its own configuration and can run independently or simultaneously (according to your license). Each client has the ability to call the `WebAPI` server (weatherforecast endpoint) to verify that authentication is working.

## 📚 Documentation & Commercial Options

For **documentation** and **commercial licensing**, visit our official website:

🔗 **[IdentitySuite Official Website](https://identitysuite.net)**

## Support

For documentation, please refer to the [IdentitySuite documentation](https://identitysuite.net/documentation). The documentation provides detailed information on how to use the library, including configuration, usage examples, and advanced features.

For issues or questions, open an [issue](https://github.com/spin973/IdentitySuite/issues) on GitHub.

## Useful links

- [What's New](https://identitysuite.net/documentation/WhatsNew)
- [Upgrade documentations](https://identitysuite.net/documentation/Migrations)
- [Changelog](https://identitysuite.net/documentation/ChangeLog)

## ⚖️ License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
