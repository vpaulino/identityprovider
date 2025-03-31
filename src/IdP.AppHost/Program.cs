var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.BackendWebApi>("backendwebapi");

builder.AddProject<Projects.BFFWebApi>("bffwebapi");

builder.AddProject<Projects.IdentityProviderApi>("identityproviderapi");

builder.AddProject<Projects.WebSiteClient>("websiteclient");

builder.Build().Run();
