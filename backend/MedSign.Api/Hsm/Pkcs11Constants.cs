namespace MedSign.Api.Hsm;

public static class Pkcs11Constants
{
    public static readonly byte[] Secp256r1 = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    public const int P256CoordinateBytes = 32;
}
