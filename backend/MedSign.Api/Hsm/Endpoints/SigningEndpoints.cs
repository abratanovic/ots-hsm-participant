using MedSign.Api.Hsm.Contracts;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;

namespace MedSign.Api.Hsm.Endpoints;

public static class SigningEndpoints
{
    public static void MapSigningEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/signing").RequireRole(Roles.Doctor);

        group.MapGet("/status", (HttpContext context, DoctorSigningKeys keys) =>
            Results.Ok(SigningStatus.Of(keys.For(context.Session().UserId))))
            .WithName("GetSigningStatus");

        group.MapPost("/enable", (HttpContext context, DoctorSigningKeys keys) =>
            Results.Ok(SigningStatus.Of(keys.Enable(context.Session().UserId))))
            .WithName("EnableSigning");
    }
}
