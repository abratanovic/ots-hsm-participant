using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MedSign.Api.Auth;
using MedSign.Api.Data;
using MedSign.Api.Hsm;

namespace MedSign.Api.Lab;

public sealed class JwtIssuer(Claims claims, ISigningProvider provider)
{
    public string IssueJwt(User user, JwtSigningKey key)
    {
        var header = new Dictionary<string, object>
        {
            ["alg"] = "ES256",
            ["typ"] = "JWT",
            ["kid"] = key.Kid,
        };

        var signingInput = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(header))
            + "."
            + Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(claims.BuildClaims(user)));

        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(signingInput));

        var signature = provider.SignDigest(key.Label, digest);

        return signingInput + "." + Base64Url.Encode(signature);
    }
}
