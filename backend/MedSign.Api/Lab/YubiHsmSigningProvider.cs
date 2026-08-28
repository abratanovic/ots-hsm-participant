using System.Security.Cryptography;
using MedSign.Api.Auth;
using MedSign.Api.Data;
using MedSign.Api.Hsm;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace MedSign.Api.Lab;

public sealed class YubiHsmSigningProvider(HsmSessionHost host, TimeProvider clock) : ISigningProvider
{
    public string Name => "YubiHSM 2";

    public JwtSigningKey ProvisionSigningKey(string label) =>
        host.Execute(hsm => CreateKeyOnDevice(hsm, label));

    public byte[] SignDigest(string label, byte[] digest) =>
        host.Execute(hsm => SignDigestOnDevice(hsm, label, digest));

    internal JwtSigningKey CreateKeyOnDevice(HsmContext hsm, string label)
    {
        if (FindPrivateKey(hsm, label) is not null)
        {
            throw new InvalidOperationException(
                $"The device already holds a private key labelled '{label}'. Provisioning again would "
                + "put two keys under one label, and signing looks the key up by label. Delete the key "
                + "on the device -- and this Provider's row in medsign.db -- to start over.");
        }

        var publicKey = GenerateKeyPair(hsm, label);

        var attribute = hsm.Session.GetAttributeValue(publicKey, [CKA.CKA_EC_POINT])[0];
        var point = EcPoint.Unwrap(attribute.GetValueAsByteArray());
        EcPoint.EnsureUncompressedP256(point);

        return new JwtSigningKey
        {
            Provider = Name,
            Label = label,
            EcPoint = point,
            Kid = Base64Url.Encode(SHA256.HashData(point)),
            CreatedAt = clock.GetUtcNow(),
        };
    }

    internal byte[] SignDigestOnDevice(HsmContext hsm, string label, byte[] digest)
    {
        var privateKey = FindPrivateKey(hsm, label)
            ?? throw new InvalidOperationException(
                $"No private key labelled '{label}' on the device, but MedSign Cloud has it recorded "
                + "as provisioned. The device was most likely reset. Delete this Provider's row in "
                + "medsign.db and POST /api/provisioning/jwt-signing again.");

        using var mechanism = hsm.Mechanisms.Create(CKM.CKM_ECDSA);

        return hsm.Session.Sign(mechanism, privateKey, digest);
    }

    private static IObjectHandle GenerateKeyPair(HsmContext hsm, string label)
    {
        List<IObjectAttribute> publicTemplate =
        [
            hsm.Attributes.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            hsm.Attributes.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
            hsm.Attributes.Create(CKA.CKA_TOKEN, true),
            hsm.Attributes.Create(CKA.CKA_VERIFY, true),
            hsm.Attributes.Create(CKA.CKA_LABEL, label),
            hsm.Attributes.Create(CKA.CKA_EC_PARAMS, Pkcs11Constants.Secp256r1),
        ];

        List<IObjectAttribute> privateTemplate =
        [
            hsm.Attributes.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            hsm.Attributes.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
            hsm.Attributes.Create(CKA.CKA_TOKEN, true),
            hsm.Attributes.Create(CKA.CKA_SIGN, true),
            hsm.Attributes.Create(CKA.CKA_SENSITIVE, true),
            hsm.Attributes.Create(CKA.CKA_EXTRACTABLE, false),
            hsm.Attributes.Create(CKA.CKA_LABEL, label),
        ];

        using var mechanism = hsm.Mechanisms.Create(CKM.CKM_EC_KEY_PAIR_GEN);
        hsm.Session.GenerateKeyPair(mechanism, publicTemplate, privateTemplate, out var publicKey, out _);

        return publicKey;
    }

    private static IObjectHandle? FindPrivateKey(HsmContext hsm, string label)
    {
        List<IObjectAttribute> template =
        [
            hsm.Attributes.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            hsm.Attributes.Create(CKA.CKA_LABEL, label),
        ];

        return hsm.Session.FindAllObjects(template).FirstOrDefault();
    }
}
