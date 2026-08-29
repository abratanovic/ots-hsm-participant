using MedSign.Api.Shared;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Tokens;

public sealed class Claims(IOptions<JwtOptions> options, TimeProvider clock)
{
    private readonly JwtOptions _jwt = options.Value;

    public Dictionary<string, object> BuildClaims(User user)
    {
        var issuedAt = clock.GetUtcNow();

        return new Dictionary<string, object>
        {
            ["iss"] = _jwt.Issuer,
            ["aud"] = _jwt.Audience,
            ["sub"] = user.Id.ToString(),
            ["preferred_username"] = user.Username,
            ["name"] = user.DisplayName,
            ["role"] = user.Role,
            ["iat"] = issuedAt.ToUnixTimeSeconds(),
            ["exp"] = issuedAt.AddMinutes(_jwt.LifetimeMinutes).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("n"),
        };
    }

    public DateTimeOffset ExpiresAt() => clock.GetUtcNow().AddMinutes(_jwt.LifetimeMinutes);
}
