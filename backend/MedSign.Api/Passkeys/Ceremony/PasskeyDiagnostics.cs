using System.Security.Cryptography;
using MedSign.Api.Shared;

namespace MedSign.Api.Passkeys;

public static class PasskeyDiagnostics
{
    private const int MaxCredentialIdBytes = 1023;

    public static string? DiagnoseRegistration(VerifiedCredential credential)
    {
        if (credential.CredentialId.Length == 0)
        {
            return "The credential id is empty. MedSign finds the account by it on every later "
                + "sign-in, so an empty one is an account nobody can sign in to. It is "
                + "RegisteredPublicKeyCredential.Id -- not the User Handle, and not the raw id "
                + "off the wire.";
        }

        if (credential.CredentialId.Length > MaxCredentialIdBytes)
        {
            return $"The credential id is {credential.CredentialId.Length} bytes; WebAuthn caps it at "
                + $"{MaxCredentialIdBytes}. A value this long is not the credential id -- check "
                + "which field was returned.";
        }

        return DiagnosePublicKey(credential.PublicKeyPoint);
    }

    private static string? DiagnosePublicKey(byte[] point)
    {
        if (point.Length != EcPoint.UncompressedP256Bytes || point[0] != 0x04)
        {
            var first = point.Length > 0 ? point[0] : (byte)0;
            return $"The public key is {point.Length} bytes starting with 0x{first:X2}; MedSign stores it "
                + $"as {EcPoint.UncompressedP256Bytes} bytes of 0x04 || X || Y. A 77-byte answer is "
                + "RegisteredPublicKeyCredential.PublicKey as the library returned it -- COSE_Key bytes, "
                + "which CosePublicKey.ToPoint converts.";
        }

        try
        {
            using var _ = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new System.Security.Cryptography.ECPoint
                {
                    X = EcPoint.X(point),
                    Y = EcPoint.Y(point),
                },
            });
        }
        catch (CryptographicException)
        {
            return "Those 64 bytes are not a point on P-256. X and Y have to satisfy the curve equation, "
                + "and random-looking bytes almost never do -- so this is a reading error, not a bad key.";
        }

        return null;
    }
}
