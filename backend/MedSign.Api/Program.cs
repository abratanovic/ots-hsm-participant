using MedSign.Api.Hsm;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Startup;
using MedSign.Api.Tokens;

var builder = WebApplication.CreateBuilder(args);
builder.AddMedSignServices();

var app = builder.Build();

app.UseMiddleware<ProblemMiddleware>();
app.UseCors();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.MapAuthEndpoints();
app.MapSigningEndpoints();
app.MapJwksEndpoints();

app.RunStartupTasks();
app.Run();
