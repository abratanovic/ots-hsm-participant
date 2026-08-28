using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Fido2NetLib;
using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;

namespace MedSign.Tests;

/// <summary>
/// A passkey in software: one P-256 key pair, one credential id, one counter.
///
/// The exercises are only worth anything if something real answers them, so this
/// stands in for the security key or the phone. It builds the same two answers a
/// browser would post back -- an attestation object for registration, a signature
/// over authenticatorData || SHA-256(clientDataJSON) for sign-in -- which means
/// Fido2NetLib verifies them for real, and a test can hand over a deliberately
/// wrong one to see what MedSign does with it.
/// </summary>
public sealed class VirtualAuthenticator : IDisposable
{
    private const byte UserPresent = 0x01;
    private const byte UserVerified = 0x04;
    private const byte AttestedCredentialData = 0x40;

    /// <summary>"none" attestation says nothing about the make of the device, so it has no id.</summary>
    private static readonly byte[] NoAaguid = new byte[16];

    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>
    /// What MedSign will know this passkey by, on every later sign-in. Set it to
    /// another authenticator's id to build the answer an impostor would send: the
    /// right credential, the wrong key.
    /// </summary>
    public byte[] CredentialId { get; init; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>Where the browser claims to be running; the relying party checks it.</summary>
    public string Origin { get; init; } = Lab.Origin;

    /// <summary>Goes up on every assertion, which is how a cloned authenticator gets caught.</summary>
    public uint SignCount { get; private set; }

    /// <summary>The public half, as MedSign stores it: 0x04 || X || Y.</summary>
    public byte[] PublicKeyPoint
    {
        get
        {
            var q = _key.ExportParameters(includePrivateParameters: false).Q;
            return [0x04, .. q.X!, .. q.Y!];
        }
    }

    /// <summary>The answer to a registration ceremony: a new key, attested with "none".</summary>
    public PasskeyRegistration Register(CredentialCreateOptions ceremony)
    {
        var clientData = ClientData("webauthn.create", ceremony.Challenge);
        var authenticatorData = AuthenticatorData(ceremony.Rp.Id, attested: true);

        return new PasskeyRegistration(
            Id: Base64Url.Encode(CredentialId),
            RawId: Base64Url.Encode(CredentialId),
            Type: "public-key",
            Transports: ["internal"],
            Response: new PasskeyRegistrationResponse(
                ClientDataJSON: Base64Url.Encode(clientData),
                AttestationObject: Base64Url.Encode(AttestationObject(authenticatorData))));
    }

    /// <summary>
    /// The answer to a sign-in ceremony. <paramref name="userHandle"/> is what the
    /// authenticator believes this key belongs to -- pass someone else's to see a
    /// relying party that does not check it hand over the wrong account.
    /// </summary>
    public PasskeyAssertion SignIn(AssertionOptions ceremony, byte[]? userHandle)
    {
        SignCount++;

        var clientData = ClientData("webauthn.get", ceremony.Challenge);
        var authenticatorData = AuthenticatorData(ceremony.RpId ?? Lab.RpId, attested: false);

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
        {"type":"{{type}}","challenge":"{{Base64Url.Encode(challenge)}}","origin":"{{Origin}}","crossOrigin":false}
        """);

    /// <summary>
    /// SHA-256(rpId) || flags || counter, and on registration the new credential
    /// itself: aaguid || id length || id || the COSE public key.
    /// </summary>
    private byte[] AuthenticatorData(string rpId, bool attested)
    {
        var counter = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(counter, SignCount);

        var flags = (byte)(UserPresent | UserVerified | (attested ? AttestedCredentialData : 0));

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
}
