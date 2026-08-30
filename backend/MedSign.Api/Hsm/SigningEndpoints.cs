using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;

namespace MedSign.Api.Hsm;

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

public sealed record SigningStatus(
    bool Enabled,
    string? PublicKeyFingerprint = null,
    DateTimeOffset? CreatedAt = null)
{
    public static SigningStatus Of(SigningKey? key) => key is null
        ? new SigningStatus(false)
        : new SigningStatus(
            true,
            SigningKey.Fingerprint(key.PublicKeyPoint),
            key.CreatedAt);
}
