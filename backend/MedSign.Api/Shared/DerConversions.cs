using System.Formats.Asn1;
using System.Security.Cryptography;

namespace MedSign.Api.Shared;

/// <summary>
/// Translations between what a cloud KMS hands back and what MedSign stores.
///
/// The YubiHSM speaks the shapes this application already uses: a signature is
/// r||s, and a public key is the 65 bytes of an uncompressed point. AWS KMS
/// speaks DER for both -- an ASN.1 SEQUENCE of two INTEGERs for the signature,
/// and an X.509 SubjectPublicKeyInfo for the key.
///
/// Neither difference is deep. Both are the same numbers in a different
/// envelope. But nothing downstream tolerates the wrong one: JwtIssuer builds a
/// JWS, which is defined over r||s, and the JWKS publishes x and y as separate
/// values. A DER signature that slipped through would be rejected by every
/// verifier on earth, which is why TokenVerifier looks for exactly this mistake.
/// </summary>
public static class DerConversions
{
    /// <summary>
    /// A DER ECDSA signature as r||s, the fixed-width form a JWS carries.
    ///
    /// DER stores r and s as signed integers of the smallest length that fits,
    /// so each arrives shorter than 32 bytes when it happens to start with zero
    /// bytes, and 33 bytes long with a leading 0x00 when its top bit is set --
    /// which would otherwise read as negative. Both cases are ordinary; roughly
    /// one signature in 256 has a short r. Left-padding to a fixed width is what
    /// puts them back on the same footing.
    /// </summary>
    public static byte[] ToFixedWidthSignature(byte[] derSignature, int coordinateBytes)
    {
        ArgumentNullException.ThrowIfNull(derSignature);

        try
        {
            var reader = new AsnReader(derSignature, AsnEncodingRules.DER);
            var sequence = reader.ReadSequence();

            var r = sequence.ReadIntegerBytes();
            var s = sequence.ReadIntegerBytes();

            sequence.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            byte[] signature = new byte[2 * coordinateBytes];
            WriteCoordinate(r.Span, signature.AsSpan(0, coordinateBytes));
            WriteCoordinate(s.Span, signature.AsSpan(coordinateBytes, coordinateBytes));

            return signature;
        }
        catch (AsnContentException exception)
        {
            throw new InvalidOperationException(
                $"Expected a DER-encoded ECDSA signature -- a SEQUENCE of two INTEGERs -- but could "
                + $"not read one from {derSignature.Length} bytes. AWS KMS returns this shape for the "
                + "ECDSA_SHA_256 signing algorithm; a YubiHSM returns r||s and needs no conversion.",
                exception);
        }
    }

    /// <summary>
    /// The public half of a DER X.509 SubjectPublicKeyInfo, as the uncompressed
    /// point MedSign stores: 0x04 || X || Y.
    /// </summary>
    public static byte[] ToUncompressedPoint(byte[] subjectPublicKeyInfo)
    {
        ArgumentNullException.ThrowIfNull(subjectPublicKeyInfo);

        using var ecdsa = ECDsa.Create();

        try
        {
            ecdsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidOperationException(
                $"Expected a DER-encoded X.509 SubjectPublicKeyInfo, which is what AWS KMS returns "
                + $"from GetPublicKey, but could not read one from {subjectPublicKeyInfo.Length} bytes.",
                exception);
        }

        var q = ecdsa.ExportParameters(includePrivateParameters: false).Q;

        byte[] point = [0x04, .. q.X!, .. q.Y!];

        // The key came off the wire, so hold it to the same standard as any other.
        EcPoint.EnsureUncompressedP256(point);

        return point;
    }

    /// <summary>
    /// One coordinate, right-aligned in a fixed-width field: leading zeros DER
    /// dropped are put back, and the padding byte DER added is left off.
    /// </summary>
    private static void WriteCoordinate(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        var trimmed = value;
        while (trimmed.Length > destination.Length && trimmed[0] == 0x00)
        {
            trimmed = trimmed[1..];
        }

        if (trimmed.Length > destination.Length)
        {
            throw new InvalidOperationException(
                $"A signature coordinate of {trimmed.Length} bytes does not fit the "
                + $"{destination.Length} bytes P-256 uses. Is this a signature from a larger curve?");
        }

        destination.Clear();
        trimmed.CopyTo(destination[(destination.Length - trimmed.Length)..]);
    }
}
