using IdentitySuite;

var builder = WebApplication.CreateBuilder(args);

// 1. Registers all required services (authentication, authorization, etc.)
builder.AddIdentitySuiteServices();

var app = builder.Build();

// 2. Creates/updates the database based on configuration
await app.SetupIdentitySuiteDbAsync();

// 3. Enables all runtime services (authentication, routing, etc.)
app.UseIdentitySuiteServices();

await app.RunAsync();