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

        // POST rather than PUT: it is a request to make sure a key exists, and
        // the caller does not get to say which one.
        group.MapPost("/enable", (HttpContext context, DoctorSigningKeys keys) =>
            Results.Ok(SigningStatus.Of(keys.Enable(context.Session().UserId))))
            .WithName("EnableSigning");
    }
}

/// <summary>
/// Whether this doctor can sign documents, and what with.
///
/// The key is named by its fingerprint and never by its PKCS#11 label. The
/// label is how MedSign addresses an object on the device; a caller has no use
/// for it, and the fingerprint is derived from the public key, so it identifies
/// the same key without handing out the name the device answers to.
///
/// Everything but <see cref="Enabled"/> is null when they cannot, and the
/// application's JSON options drop nulls, so the answer is a bare
/// { "enabled": false } rather than a shape full of empty strings the frontend
/// would render as placeholder text.
/// </summary>
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
