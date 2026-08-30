using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Fido2NetLib;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;

namespace MedSign.Tests;

public sealed class VirtualAuthenticator : IDisposable
{
    private const byte UserPresent = 0x01;
    private const byte UserVerifiedFlag = 0x04;
    private const byte AttestedCredentialData = 0x40;

    private static readonly byte[] NoAaguid = new byte[16];

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public byte[] CredentialId { get; init; } = RandomNumberGenerator.GetBytes(32);

    public string Origin { get; init; } = Lab.Origin;

    public string? RpIdOverride { get; init; }

    public string? ClientDataTypeOverride { get; init; }

    public uint SignCount { get; set; }

    public byte[] PublicKeyPoint
    {
        get
        {
            var q = _key.ExportParameters(includePrivateParameters: false).Q;
            return [0x04, .. q.X!, .. q.Y!];
        }
    }

    public PasskeyRegistration Register(CredentialCreateOptions ceremony) =>
        Register(ceremony.Challenge, ceremony.Rp.Id);

    public PasskeyRegistration Register(byte[] challenge, string rpId)
    {
        var clientData = ClientData("webauthn.create", challenge);
        var authenticatorData = AuthenticatorData(RpIdOverride ?? rpId, attested: true);

        return new PasskeyRegistration(
            Id: Base64Url.Encode(CredentialId),
            RawId: Base64Url.Encode(CredentialId),
            Type: "public-key",
            Transports: ["internal"],
            Response: new PasskeyRegistrationResponse(
                ClientDataJSON: Base64Url.Encode(clientData),
                AttestationObject: Base64Url.Encode(AttestationObject(authenticatorData))));
    }

    public PasskeyAssertion SignIn(AssertionOptions ceremony, byte[]? userHandle) =>
        SignIn(ceremony.Challenge, ceremony.RpId ?? Lab.RpId, userHandle);

    public PasskeyAssertion SignIn(byte[] challenge, string rpId, byte[]? userHandle)
    {
        SignCount++;

        var clientData = ClientData("webauthn.get", challenge);
        var authenticatorData = AuthenticatorData(RpIdOverride ?? rpId, attested: false);

        var signature = _key.SignData(
            [.. authenticatorData, .. SHA256.HashData(clientData)],
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        return new PasskeyAssertion(
            Id: Base64Url.Encode(CredentialId),
            RawId: Base64Url.Encode(CredentialId),
            Type: "public-key",
            Response: new PasskeyAssertionResponse(
                ClientDataJSON: Base64Url.Encode(clientData),
                AuthenticatorData: Base64Url.Encode(authenticatorData),
                Signature: Base64Url.Encode(signature),
                UserHandle: userHandle is null ? null : Base64Url.Encode(userHandle)));
    }

    public void Dispose() => _key.Dispose();

    private byte[] ClientData(string type, byte[] challenge) => Encoding.UTF8.GetBytes(
        $$"""
        {"type":"{{ClientDataTypeOverride ?? type}}","challenge":"{{Base64Url.Encode(challenge)}}","origin":"{{Origin}}","crossOrigin":false}
        """);

    private byte[] AuthenticatorData(string rpId, bool attested)
    {
        var counter = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(counter, SignCount);

        var flags = (byte)(UserPresent | UserVerifiedFlag | (attested ? AttestedCredentialData : 0));

        byte[] header = [.. SHA256.HashData(Encoding.UTF8.GetBytes(rpId)), flags, .. counter];

        if (!attested)
        {
            return header;
        }

        var idLength = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(idLength, (ushort)CredentialId.Length);

        return
        [
            .. header,
            .. NoAaguid,
            .. idLength,
            .. CredentialId,
            .. CosePublicKey.FromPoint(PublicKeyPoint),
        ];
    }

    private static byte[] AttestationObject(byte[] authenticatorData)
    {
        var cbor = new CborWriter();

        cbor.WriteStartMap(3);

        cbor.WriteTextString("fmt");
        cbor.WriteTextString("none");

        cbor.WriteTextString("attStmt");
        cbor.WriteStartMap(0);
        cbor.WriteEndMap();

        cbor.WriteTextString("authData");
        cbor.WriteByteString(authenticatorData);

        cbor.WriteEndMap();

        return cbor.Encode();
    }

    public static string Flip(string base64UrlValue, int index = 0)
    {
        var bytes = Base64Url.Decode(base64UrlValue);
        bytes[index] ^= 0xFF;

        return Base64Url.Encode(bytes);
    }
}
