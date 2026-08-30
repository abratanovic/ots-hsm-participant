using MedSign.Api.Shared;

namespace MedSign.Api.Tokens;

public sealed class SessionIssuer(
    IJwtSigningKeyStore keys,
    JwtIssuer issuer,
    Claims claims,
    IJwtSigningProvider provider,
    SigningKeyStatus signingKey)
{
    public object Issue(User user)
    {
        var key = keys.Current() ?? throw signingKey.SigningKeyMissing(provider.Name);

        var token = issuer.IssueJwt(user, key);

        if (TokenVerifier.Diagnose(token, key) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }

        return new
        {
            token,
            expiresAt = claims.ExpiresAt(),
            user = new
            {
                id = user.Id,
                username = user.Username,
                fullName = user.DisplayName,
                role = user.Role,
            },
        };
    }
}
