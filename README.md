# IdentitySuite Demo Projects

This repository contains two demo projects that demonstrate how to configure the **IdentitySuite** library in different scenarios.

## Repository Structure

- **BasicConfiguration**: Minimum configuration required to get IdentitySuite up and running.
- **AdvancedConfiguration**: Advanced example with customization of OpenIddict endpoints.

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

## Support

For issues or questions, open an [issue](https://github.com/spin973/IdentitySuite/issues) on GitHub.
