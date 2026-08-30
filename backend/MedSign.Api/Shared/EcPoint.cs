using System.Security.Cryptography;
using MedSign.Api.Hsm;

namespace MedSign.Api.Shared;

public static class EcPoint
{
    public const int UncompressedP256Bytes = 1 + 2 * Pkcs11Constants.P256CoordinateBytes;

    public static byte[] Unwrap(byte[] attributeValue)
    {
        if (attributeValue.Length == UncompressedP256Bytes && attributeValue[0] == 0x04)
        {
            return attributeValue;
        }

        if (attributeValue.Length >= 2 && attributeValue[0] == 0x04)
        {
            var lengthByte = attributeValue[1];
            var offset = lengthByte < 0x80 ? 2 : 2 + (lengthByte & 0x7F);
            if (offset < attributeValue.Length)
            {
                return attributeValue[offset..];
            }
        }

        return attributeValue;
    }

    public static byte[] X(byte[] point) => point[1..(1 + Pkcs11Constants.P256CoordinateBytes)];

    public static byte[] Y(byte[] point) => point[(1 + Pkcs11Constants.P256CoordinateBytes)..];

    public static ECDsa Verifier(byte[] point)
    {
        EnsureUncompressedP256(point);

        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = X(point), Y = Y(point) },
        });
    }

    public static void EnsureUncompressedP256(byte[] point)
    {
        if (point.Length != UncompressedP256Bytes || point[0] != 0x04)
        {
            var first = point.Length > 0 ? point[0] : (byte)0;
            throw new InvalidOperationException(
                $"Expected a {UncompressedP256Bytes}-byte uncompressed P-256 point starting with 0x04, "
                + $"got {point.Length} bytes starting with 0x{first:X2}. "
                + "Did you store the CKA_EC_POINT attribute without calling EcPoint.Unwrap?");
        }
    }
}
