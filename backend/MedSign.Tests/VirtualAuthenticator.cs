using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using Fido2NetLib;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;

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
    private const byte UserVerifiedFlag = 0x04;
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

    /// <summary>
    /// The relying party this key signs for, when it is not the one that asked.
    /// A passkey made for another site produces the right shape and the wrong
    /// rpIdHash, which is the whole point of binding a credential to a domain.
    /// </summary>
    public string? RpIdOverride { get; init; }

    /// <summary>
    /// Overrides the ceremony type written into clientDataJSON ("webauthn.create"
    /// on registration, "webauthn.get" on sign-in). Set it to the other one to
    /// replay a registration answer into a sign-in, or the reverse.
    /// </summary>
    public string? ClientDataTypeOverride { get; init; }

    /// <summary>
    /// Goes up on every assertion, which is how a cloned authenticator gets caught.
    /// Settable so a test can put this key exactly where the stored counter is.
    /// </summary>
    public uint SignCount { get; set; }

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
    public PasskeyRegistration Register(CredentialCreateOptions ceremony) =>
        Register(ceremony.Challenge, ceremony.Rp.Id);

    /// <summary>
    /// The same answer, built from a ceremony that arrived as JSON rather than as
    /// library objects -- which is what the endpoint tests have to work from.
    /// </summary>
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

    /// <summary>
    /// The answer to a sign-in ceremony. <paramref name="userHandle"/> is what the
    /// authenticator believes this key belongs to -- pass someone else's to see a
    /// relying party that does not check it hand over the wrong account.
    /// </summary>
    public PasskeyAssertion SignIn(AssertionOptions ceremony, byte[]? userHandle) =>
        SignIn(ceremony.Challenge, ceremony.RpId ?? Lab.RpId, userHandle);

    /// <summary>The same answer, built from a ceremony that arrived as JSON.</summary>
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

    /// <summary>
    /// SHA-256(rpId) || flags || counter, and on registration the new credential
    /// itself: aaguid || id length || id || the COSE public key.
    /// </summary>
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

    /// <summary>
    /// Changes one byte of a base64url field, leaving everything around it intact.
    ///
    /// This is what an answer that was interfered with in flight looks like: the
    /// shapes all still parse, and only the signature says so.
    /// </summary>
    public static string Flip(string base64UrlValue, int index = 0)
    {
        var bytes = Base64Url.Decode(base64UrlValue);
        bytes[index] ^= 0xFF;

        return Base64Url.Encode(bytes);
    }
}
