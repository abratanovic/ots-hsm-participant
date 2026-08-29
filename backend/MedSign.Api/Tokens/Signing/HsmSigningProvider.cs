using System.Security.Cryptography;
using MedSign.Api.Hsm;
using MedSign.Api.Shared;

namespace MedSign.Api.Tokens;

public sealed class HsmJwtSigningProvider(TimeProvider clock, HsmCommunicator hsm) : IJwtSigningProvider
{
    public string Name => "HSM";

    public JwtSigningKey ProvisionSigningKey(string label)
    {
        var point = hsm.GetKey(label) ?? hsm.CreateKey(label);

        return new JwtSigningKey
        {
            Provider = Name,
            Label = label,
            EcPoint = point,
            Kid = Base64Url.Encode(SHA256.HashData(point)),
            CreatedAt = clock.GetUtcNow(),
        };
    }

    public byte[] SignDigest(string label, byte[] digest) => hsm.SignDigest(label, digest);
}
