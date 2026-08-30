using MedSign.Api.Tokens;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Shared.Auth;

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
