using System.Security.Cryptography;
using Fido2NetLib.Objects;
using MedSign.Api.Shared;

namespace MedSign.Api.Passkeys;

public static class CosePublicKey
{
    public static byte[] ToPoint(byte[] coseKey)
    {
        using var ecdsa = new CredentialPublicKey(coseKey).CreateECDsa();
        var q = ecdsa.ExportParameters(false).Q;

        return [0x04, .. q.X!, .. q.Y!];
    }

    public static byte[] FromPoint(byte[] point)
    {
        EcPoint.EnsureUncompressedP256(point);

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new System.Security.Cryptography.ECPoint
            {
                X = EcPoint.X(point),
                Y = EcPoint.Y(point),
            },
        });

        return new CredentialPublicKey(ecdsa, COSE.Algorithm.ES256).GetBytes();
    }
}
