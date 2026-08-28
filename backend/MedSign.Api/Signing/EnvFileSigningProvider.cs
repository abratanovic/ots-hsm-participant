using System.Security.Cryptography;
using MedSign.Api.Auth;
using MedSign.Api.Data;
using MedSign.Api.Hsm;

namespace MedSign.Api.Signing;

public sealed class EnvFileSigningProvider(IHostEnvironment environment, TimeProvider clock) : ISigningProvider
{
    public const string KeyVariable = "MEDSIGN_JWT_SIGNING_KEY";

    private const string KeyComment =
        "The JWT signing key: an EC P-256 private key, PKCS#8, base64.\n"
        + "Generated on first run. Anyone who can read this line can mint a doctor token\n"
        + "for any account on this MedSign instance. Exercise 2 is about fixing that.";

    private readonly string _envPath = Path.Combine(environment.ContentRootPath, ".env");
    private readonly Lock _gate = new();

    public string Name => "Local .env file";

    public JwtSigningKey ProvisionSigningKey(string label)
    {
        lock (_gate)
        {
            using var ecdsa = Load() ?? Generate();
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
    }

    public byte[] SignDigest(string label, byte[] digest)
    {
        lock (_gate)
        {
            using var ecdsa = Load()
                ?? throw new InvalidOperationException(
                    $"No signing key in {_envPath}. MedSign Cloud recorded one as provisioned, but "
                    + $"{KeyVariable} is gone from the file -- which is all it took to lock everyone "
                    + "out of the product. Delete medsign.db and restart to generate a new one.");

            return ecdsa.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
    }

    public string KeyPath => _envPath;

    private ECDsa? Load()
    {
        if (!DotEnv.Read(_envPath).TryGetValue(KeyVariable, out var encoded)
            || string.IsNullOrWhiteSpace(encoded))
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
                $"{KeyVariable} in {_envPath} is not a base64 PKCS#8 private key. Delete the line and "
                + "restart to generate a new one -- and note how little it took to corrupt it.",
                exception);
        }

        return ecdsa;
    }

    private ECDsa Generate()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DotEnv.Write(_envPath, KeyVariable, Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey()), KeyComment);
        return ecdsa;
    }

    private static byte[] UncompressedPoint(ECDsa ecdsa)
    {
        var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        return [0x04, .. parameters.Q.X!, .. parameters.Q.Y!];
    }
}
