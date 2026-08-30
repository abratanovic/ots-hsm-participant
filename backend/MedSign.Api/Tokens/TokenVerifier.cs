using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MedSign.Api.Hsm;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;

namespace MedSign.Api.Tokens;

public static class TokenVerifier
{
    public static string? Diagnose(string token, JwtSigningKey key)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            return $"A JWS has three dot-separated segments; this one has {parts.Length}. "
                + "Expected base64url(header) + \".\" + base64url(payload) + \".\" + base64url(signature).";
        }

        byte[] header, payload, signature;
        try
        {
            header = Base64Url.Decode(parts[0]);
            payload = Base64Url.Decode(parts[1]);
            signature = Base64Url.Decode(parts[2]);
        }
        catch (FormatException)
        {
            return "A segment is not valid base64url. Use Base64Url.Encode -- standard base64 "
                + "produces '+', '/' and '=' characters, none of which are allowed here.";
        }

        if (payload.Length == 0)
        {
            return "The payload segment is empty. It should be the JSON from Claims.BuildClaims.";
        }

        var headerProblem = DiagnoseHeader(header, key);
        if (headerProblem is not null)
        {
            return headerProblem;
        }

        if (signature.Length != 2 * Pkcs11Constants.P256CoordinateBytes)
        {
            return $"The signature is {signature.Length} bytes; ES256 needs exactly 64, "
                + "raw R||S. A signature of about 70 bytes starting with 0x30 is a DER SEQUENCE. "
                + "The YubiHSM returns raw R||S already, so nothing needs converting on this path.";
        }

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        var digest = SHA256.HashData(signingInput);

        using var ecdsa = PublicKey(key);
        if (!ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        {
            return "The signature does not verify against the provisioned key. The bytes signed must be "
                + "SHA-256 over the ASCII of base64url(header) + \".\" + base64url(payload), and nothing "
                + "else -- CKM_ECDSA does not hash for you, so hand it a 32-byte digest exactly once.";
        }

        return null;
    }

    public static SessionReview ReviewSession(
        string token, JwtSigningKey key, JwtOptions jwt, DateTimeOffset now)
    {
        if (Diagnose(token, key) is { } problem)
        {
            return SessionReview.Refused(problem);
        }

        JsonElement claims;
        try
        {
            claims = JsonDocument.Parse(Base64Url.Decode(token.Split('.')[1])).RootElement;
        }
        catch (JsonException)
        {
            return SessionReview.Refused("The payload segment is not JSON.");
        }

        if (Text(claims, "iss") is var issuer && issuer != jwt.Issuer)
        {
            return SessionReview.Refused(
                $"The token says iss={issuer ?? "(missing)"}; this MedSign issues {jwt.Issuer}. "
                + "A token minted somewhere else is not a session here.");
        }

        if (Text(claims, "aud") is var audience && audience != jwt.Audience)
        {
            return SessionReview.Refused(
                $"The token says aud={audience ?? "(missing)"}; this MedSign answers to {jwt.Audience}.");
        }

        if (Seconds(claims, "exp") is not { } expiresAt)
        {
            return SessionReview.Refused(
                "The token has no exp claim, so it would never stop being a session.");
        }

        if (expiresAt <= now)
        {
            return SessionReview.Refused($"This session expired at {expiresAt:u}. Sign in again.");
        }

        if (!int.TryParse(Text(claims, "sub"), out var userId))
        {
            return SessionReview.Refused(
                $"The token says sub={Text(claims, "sub") ?? "(missing)"}, which is not an account id.");
        }

        var role = Text(claims, "role");
        if (!Roles.IsKnown(role))
        {
            return SessionReview.Refused(
                $"The token says role={role ?? "(missing)"}; MedSign knows {Roles.All}.");
        }

        return SessionReview.Accepted(new SessionPrincipal(
            userId,
            Text(claims, "preferred_username") ?? string.Empty,
            Text(claims, "name") ?? string.Empty,
            role!));
    }

    private static string? Text(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static DateTimeOffset? Seconds(JsonElement claims, string name) =>
        claims.TryGetProperty(name, out var value)
        && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt64(out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;

    private static string? DiagnoseHeader(byte[] header, JwtSigningKey key)
    {
        JsonElement parsed;
        try
        {
            parsed = JsonDocument.Parse(header).RootElement;
        }
        catch (JsonException)
        {
            return "The header segment is not JSON.";
        }

        var alg = parsed.TryGetProperty("alg", out var algValue) ? algValue.GetString() : null;
        if (alg != "ES256")
        {
            return $"The header says alg={alg ?? "(missing)"}; it must say ES256, which is ECDSA "
                + "on P-256 with SHA-256 -- exactly what the Signing Key can do.";
        }

        var kid = parsed.TryGetProperty("kid", out var kidValue) ? kidValue.GetString() : null;
        if (kid != key.Kid)
        {
            return $"The header says kid={kid ?? "(missing)"}; the provisioned key is {key.Kid}. "
                + "A verifier uses kid to pick a key out of the JWKS, so it has to match.";
        }

        return null;
    }

    public static ECDsa PublicKey(JwtSigningKey key) => EcPoint.Verifier(key.EcPoint);
}
