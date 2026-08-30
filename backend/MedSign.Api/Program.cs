using MedSign.Api.Endpoints;
using MedSign.Api.Hsm;
using MedSign.Api.Passkeys;
using MedSign.Api.Startup;

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
app.MapJwksEndpoints();

app.RunStartupTasks();
app.Run();
