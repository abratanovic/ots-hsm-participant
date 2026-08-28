using Fido2NetLib;
using Fido2NetLib.Objects;
using static MedSign.Api.Auth.Passkey.WebAuthnEnums;

namespace MedSign.Api.Auth.Passkey;

public static class PasskeyWire
{

    public static PasskeyCreationChallenge ToWire(CredentialCreateOptions options) =>
        new(
            Challenge: Base64Url.Encode(options.Challenge),
            Rp: new RelyingParty(options.Rp.Id, options.Rp.Name),
            User: new PasskeyUser(
                Id: Base64Url.Encode(options.User.Id),
                Name: options.User.Name,
                DisplayName: options.User.DisplayName),
            PubKeyCredParams: [.. options.PubKeyCredParams.Select(p => new PasskeyAlgorithm("public-key", (int)p.Alg))],
            Timeout: (int)options.Timeout,
            Attestation: Wire(options.Attestation),
            AuthenticatorSelection: new AuthenticatorSelection(
                ResidentKey: Wire(options.AuthenticatorSelection.ResidentKey),
                UserVerification: Wire(options.AuthenticatorSelection.UserVerification)),
            ExcludeCredentials: [.. options.ExcludeCredentials.Select(ToWire)]);

    public static PasskeyChallenge ToWire(AssertionOptions options) =>
        new(
            Challenge: Base64Url.Encode(options.Challenge),
            RpId: options.RpId ?? string.Empty,
            Timeout: (int)options.Timeout,
            UserVerification: Wire(options.UserVerification ?? UserVerificationRequirement.Preferred),

            AllowCredentials: options.AllowCredentials.Count == 0
                ? null
                : [.. options.AllowCredentials.Select(ToWire)]);

    private static PasskeyDescriptor ToWire(PublicKeyCredentialDescriptor descriptor) =>
        new(Base64Url.Encode(descriptor.Id),
            descriptor.Transports is null ? null : [.. descriptor.Transports.Select(Wire)]);

    public static AuthenticatorAttestationRawResponse ToRaw(PasskeyRegistration credential) => new()
    {
        Id = credential.Id,
        RawId = Base64Url.Decode(credential.RawId),
        Type = CredentialType(credential.Type),
        Response = new AuthenticatorAttestationRawResponse.AttestationResponse
        {
            AttestationObject = Base64Url.Decode(credential.Response.AttestationObject),
            ClientDataJson = Base64Url.Decode(credential.Response.ClientDataJSON),
            Transports = Transports(credential.Transports),
        },
        ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
    };

    public static AuthenticatorAssertionRawResponse ToRaw(PasskeyAssertion assertion) => new()
    {
        Id = assertion.Id,
        RawId = Base64Url.Decode(assertion.RawId),
        Type = CredentialType(assertion.Type),
        Response = new AuthenticatorAssertionRawResponse.AssertionResponse
        {
            AuthenticatorData = Base64Url.Decode(assertion.Response.AuthenticatorData),
            Signature = Base64Url.Decode(assertion.Response.Signature),
            ClientDataJson = Base64Url.Decode(assertion.Response.ClientDataJSON),

            UserHandle = string.IsNullOrEmpty(assertion.Response.UserHandle)
                ? null
                : Base64Url.Decode(assertion.Response.UserHandle),
        },
        ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
    };
}
