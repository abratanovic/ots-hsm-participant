using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Data;
using MedSign.Api.Hsm;
using MedSign.Api.Signing;
using Fido2NetLib;

namespace MedSign.Tests;

public class ClaimsTests
{
    private static Claims For(TimeProvider clock, int lifetimeMinutes = 60) =>
        new(Build.Options(new JwtOptions
        {
            Issuer = "https://medsign.example",
            Audience = "medsign-cloud",
            LifetimeMinutes = lifetimeMinutes,
        }), clock);

    [Fact]
    public void Carries_the_identity_the_frontend_reads()
    {
        var claims = For(new TestClock()).BuildClaims(Build.Doctor());

        Assert.Equal("https://medsign.example", claims["iss"]);
        Assert.Equal("medsign-cloud", claims["aud"]);
        Assert.Equal("7", claims["sub"]);
        Assert.Equal("h.novak", claims["preferred_username"]);
        Assert.Equal(Roles.Doctor, claims["role"]);
    }

    [Fact]
    public void Expires_exactly_one_lifetime_after_it_is_issued()
    {
        var claims = For(new TestClock(), lifetimeMinutes: 15).BuildClaims(Build.Doctor());

        Assert.Equal(15 * 60, (long)claims["exp"] - (long)claims["iat"]);
    }

    [Fact]
    public void Gives_every_token_a_different_jti()
    {
        var claims = For(new TestClock());

        Assert.NotEqual(claims.BuildClaims(Build.Doctor())["jti"], claims.BuildClaims(Build.Doctor())["jti"]);
    }
}

/// <summary>
/// The .env provider is exercise 1's "before" picture. It has to actually work --
/// the point of the exercise is that it works and is still a bad idea.
/// </summary>
public class EnvFileSigningProviderTests
{
    [Fact]
    public void Generates_a_key_on_first_use_and_writes_it_to_the_env_file()
    {
        using var root = new TempContentRoot();
        var provider = new EnvFileSigningProvider(root, new TestClock());

        var key = provider.ProvisionSigningKey("medsign-jwt-signing");

        Assert.True(File.Exists(root.EnvPath));
        Assert.NotEmpty(DotEnv.Read(root.EnvPath)[EnvFileSigningProvider.KeyVariable]);
        Assert.Equal("medsign-jwt-signing", key.Label);
        EcPoint.EnsureUncompressedP256(key.EcPoint);
    }

    [Fact]
    public void Derives_the_kid_from_the_public_point()
    {
        using var root = new TempContentRoot();

        var key = new EnvFileSigningProvider(root, new TestClock()).ProvisionSigningKey("k");

        Assert.Equal(Base64Url.Encode(SHA256.HashData(key.EcPoint)), key.Kid);
    }

    [Fact]
    public void Reuses_the_key_already_in_the_file_instead_of_rotating_it()
    {
        using var root = new TempContentRoot();
        var provider = new EnvFileSigningProvider(root, new TestClock());

        Assert.Equal(provider.ProvisionSigningKey("k").Kid, provider.ProvisionSigningKey("k").Kid);
    }

    [Fact]
    public void Produces_a_signature_the_public_point_verifies()
    {
        using var root = new TempContentRoot();
        var provider = new EnvFileSigningProvider(root, new TestClock());
        var key = provider.ProvisionSigningKey("k");
        var digest = SHA256.HashData("a prescription"u8.ToArray());

        var signature = provider.SignDigest("k", digest);

        Assert.Equal(64, signature.Length); // Raw R||S, not DER -- JWS requires it.
        Assert.True(Verify.P256(key.EcPoint, digest, signature));
    }

    [Fact]
    public void Says_so_clearly_when_the_key_line_has_been_corrupted()
    {
        using var root = new TempContentRoot();
        var provider = new EnvFileSigningProvider(root, new TestClock());
        provider.ProvisionSigningKey("k");
        DotEnv.Write(root.EnvPath, EnvFileSigningProvider.KeyVariable, "not-a-key");

        var failure = Assert.Throws<InvalidOperationException>(() => provider.ProvisionSigningKey("k"));

        Assert.Contains("PKCS#8", failure.Message);
    }
}

/// <summary>
/// The JWT MedSign issues has to be a real ES256 token: three segments, a kid the
/// JWKS can be looked up by, and a signature over exactly the bytes a verifier
/// will reconstruct. Getting the signing input even one byte wrong still produces
/// a token that looks fine and verifies nowhere.
/// </summary>
public class JwtIssuerTests
{
    private sealed record Issued(string Token, JwtSigningKey Key);

    private static Issued Issue(TempContentRoot root)
    {
        var clock = new TestClock();
        var provider = new EnvFileSigningProvider(root, clock);
        var key = provider.ProvisionSigningKey("medsign-jwt-signing");
        var claims = new Claims(Build.Options(new JwtOptions()), clock);

        return new Issued(new JwtIssuer(claims, provider).IssueJwt(Build.Doctor(), key), key);
    }

    [Fact]
    public void Issues_three_dot_separated_segments()
    {
        using var root = new TempContentRoot();

        Assert.Equal(3, Issue(root).Token.Split('.').Length);
    }

    [Fact]
    public void Names_ES256_and_the_kid_in_the_header()
    {
        using var root = new TempContentRoot();
        var issued = Issue(root);

        var header = JsonDocument.Parse(Base64Url.Decode(issued.Token.Split('.')[0])).RootElement;

        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.GetProperty("typ").GetString());
        Assert.Equal(issued.Key.Kid, header.GetProperty("kid").GetString());
    }

    [Fact]
    public void Carries_the_signed_in_account_in_the_payload()
    {
        using var root = new TempContentRoot();

        var payload = JsonDocument.Parse(Base64Url.Decode(Issue(root).Token.Split('.')[1])).RootElement;

        Assert.Equal("7", payload.GetProperty("sub").GetString());
        Assert.Equal(Roles.Doctor, payload.GetProperty("role").GetString());
    }

    [Fact]
    public void Signs_the_header_and_payload_that_a_verifier_will_reconstruct()
    {
        using var root = new TempContentRoot();
        var issued = Issue(root);
        var segments = issued.Token.Split('.');

        var signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{segments[1]}");

        Assert.True(Verify.P256(issued.Key.EcPoint, SHA256.HashData(signingInput), Base64Url.Decode(segments[2])));
    }

    [Fact]
    public void Does_not_verify_once_a_claim_has_been_tampered_with()
    {
        using var root = new TempContentRoot();
        var issued = Issue(root);
        var segments = issued.Token.Split('.');

        var forged = Base64Url.Encode(
            Encoding.UTF8.GetBytes(
                Encoding.UTF8.GetString(Base64Url.Decode(segments[1])).Replace("\"patient\"", "\"doctor\"")
                    + " "));

        var signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{forged}");

        Assert.False(Verify.P256(issued.Key.EcPoint, SHA256.HashData(signingInput), Base64Url.Decode(segments[2])));
    }
}

internal static class Verify
{
    public static bool P256(byte[] point, byte[] digest, byte[] signature)
    {
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = EcPoint.X(point), Y = EcPoint.Y(point) },
        });

        return ecdsa.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}
