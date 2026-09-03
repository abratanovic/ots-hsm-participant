using System.Security.Cryptography;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;

namespace MedSign.Api.Cloud.Kms;

/// <summary>
/// The JWT signing key, held in AWS KMS instead of on the YubiHSM.
///
/// Line for line the same as HsmJwtSigningProvider with a different device
/// behind it, which is the whole argument: JwtIssuer hands a digest to whatever
/// is registered and publishes the point it gets back. It never learns which.
/// </summary>
public sealed class KmsJwtSigningProvider(TimeProvider clock, KmsCommunicator kms) : IJwtSigningProvider
{
    // Stored on the key row and matched on read, so the name is effectively
    // schema: changing it orphans keys provisioned under the old one.
    public string Name => "AWS KMS";

    public JwtSigningKey ProvisionSigningKey(string label)
    {
        var point = kms.GetKey(label) ?? kms.CreateKey(label);

        return new JwtSigningKey
        {
            Provider = Name,
            Label = label,
            EcPoint = point,
            Kid = Base64Url.Encode(SHA256.HashData(point)),
            CreatedAt = clock.GetUtcNow(),
        };
    }

    public byte[] SignDigest(string label, byte[] digest) => kms.SignDigest(label, digest);
}
