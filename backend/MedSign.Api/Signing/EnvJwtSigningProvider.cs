using System.Security.Cryptography;
using MedSign.Api.Auth;
using MedSign.Api.Data;
using MedSign.Api.Hsm;

namespace MedSign.Api.Signing;

/// <summary>
/// Exercise 1's "before" picture: the JWT signing key as a base64 PKCS#8 blob in an
/// environment variable, which docker-compose.yml pins and .env can override.
///
/// It works, and it is still a bad idea. The private key is readable by anything that
/// can read the process environment, it is committed to this repository in plain sight,
/// and every participant on this workshop is signing with the same one.
/// </summary>
public sealed class EnvJwtSigningProvider(IConfiguration configuration, TimeProvider clock) : IJwtSigningProvider
{
    public const string KeyVariable = "MEDSIGN_JWT_SIGNING_KEY";

    public string Name => "Local .env file";

    public JwtSigningKey ProvisionSigningKey(string label)
    {
        using var ecdsa = Load() ?? throw Missing();
        var point = UncompressedPoint(ecdsa);

        return new JwtSigningKey
        {
            Provider = Name,
            Label = label,
            EcPoint = point,
            Kid = Base64Url.Encode(SHA256.HashData(point)),
            CreatedAt = clock.GetUtcNow(),
        };
    }

    public byte[] SignDigest(string label, byte[] digest)
    {
        using var ecdsa = Load()
            ?? throw new InvalidOperationException(
                $"No signing key. MedSign Cloud recorded one as provisioned, but {KeyVariable} is gone "
                + "from the environment -- which is all it took to lock everyone out of the product. "
                + "Put the key back and restart.");

        return ecdsa.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private ECDsa? Load()
    {
        var encoded = configuration[KeyVariable];
        if (string.IsNullOrWhiteSpace(encoded))
        {
            return null;
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(encoded), out _);
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            ecdsa.Dispose();
            throw new InvalidOperationException(
                $"{KeyVariable} is not a base64 PKCS#8 private key. Replace it and restart -- and note "
                + "how little it took to corrupt it. One stray character in a plaintext variable takes "
                + "every doctor's sign-in with it.",
                exception);
        }

        return ecdsa;
    }

    private static InvalidOperationException Missing() =>
        new($"No JWT signing key: {KeyVariable} is unset or empty. docker-compose.yml pins one and .env "
            + "overrides it, so set it in either and restart. MedSign cannot mint a key for itself here: "
            + "a process cannot write to its own environment.");

    private static byte[] UncompressedPoint(ECDsa ecdsa)
    {
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        return [0x04, .. parameters.Q.X!, .. parameters.Q.Y!];
    }
}
