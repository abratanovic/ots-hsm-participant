using MedSign.Api.Tokens;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Shared.Auth;

/// <summary>
/// Reads the session back off the wire.
///
/// MedSign issues its own tokens with its own key, so the full ASP.NET bearer
/// stack would have to be pointed at this application's key set to validate
/// them -- an HTTP round trip from the process to itself. <see cref="TokenVerifier"/>
/// already holds the check the JWKS endpoint publishes the key for, so this
/// middleware is the whole of it.
///
/// It never refuses a request. A token that does not stand up leaves the
/// request anonymous with the reason recorded, and the endpoint's own role
/// requirement decides what that means -- which is what keeps the sign-in and
/// registration ceremonies reachable without one.
/// </summary>
public sealed class SessionMiddleware(RequestDelegate next, ILogger<SessionMiddleware> log)
{
    private const string Scheme = "Bearer ";

    public async Task InvokeAsync(
        HttpContext context,
        IJwtSigningKeyStore keys,
        IOptions<JwtOptions> jwt,
        TimeProvider clock)
    {
        if (Presented(context.Request) is { } token)
        {
            context.Attach(Review(token, keys, jwt.Value, clock), log);
        }

        await next(context);
    }

    private static SessionReview Review(
        string token, IJwtSigningKeyStore keys, JwtOptions jwt, TimeProvider clock)
    {
        if (keys.Current() is not { } key)
        {
            return SessionReview.Refused(
                "MedSign Cloud has no JWT Signing Key, so it cannot check the token it issued you.");
        }

        return TokenVerifier.ReviewSession(token, key, jwt, clock.GetUtcNow());
    }

    /// <summary>
    /// The bearer credential, or null when the caller offered no session at all.
    /// A header that is present but not a bearer token counts as offering one:
    /// it is a mistake worth naming rather than silent anonymity.
    /// </summary>
    private static string? Presented(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();

        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        return header.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase)
            ? header[Scheme.Length..].Trim()
            : header.Trim();
    }
}
