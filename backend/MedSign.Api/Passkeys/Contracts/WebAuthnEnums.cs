using Fido2NetLib.Objects;

namespace MedSign.Api.Passkeys;

public static class WebAuthnEnums
{
    public static AuthenticatorTransport[] Transports(IEnumerable<string> transports) =>
        [.. transports.Select(Transport).OfType<AuthenticatorTransport>()];

    public static string Wire(AuthenticatorTransport transport) => transport switch
    {
        AuthenticatorTransport.Usb => "usb",
        AuthenticatorTransport.Nfc => "nfc",
        AuthenticatorTransport.Ble => "ble",
        AuthenticatorTransport.SmartCard => "smart-card",
        AuthenticatorTransport.Hybrid => "hybrid",
        _ => "internal",
    };

    public static string Wire(AttestationConveyancePreference attestation) => attestation switch
    {
        AttestationConveyancePreference.Indirect => "indirect",
        AttestationConveyancePreference.Direct => "direct",
        AttestationConveyancePreference.Enterprise => "enterprise",
        _ => "none",
    };

    public static string Wire(ResidentKeyRequirement residentKey) => residentKey switch
    {
        ResidentKeyRequirement.Required => "required",
        ResidentKeyRequirement.Preferred => "preferred",
        _ => "discouraged",
    };

    public static string Wire(UserVerificationRequirement userVerification) => userVerification switch
    {
        UserVerificationRequirement.Required => "required",
        UserVerificationRequirement.Discouraged => "discouraged",
        _ => "preferred",
    };

    public static PublicKeyCredentialType CredentialType(string type) =>
        type == "public-key" ? PublicKeyCredentialType.PublicKey : PublicKeyCredentialType.Invalid;

    private static AuthenticatorTransport? Transport(string value) => value switch
    {
        "usb" => AuthenticatorTransport.Usb,
        "nfc" => AuthenticatorTransport.Nfc,
        "ble" => AuthenticatorTransport.Ble,
        "smart-card" => AuthenticatorTransport.SmartCard,
        "hybrid" => AuthenticatorTransport.Hybrid,
        "internal" => AuthenticatorTransport.Internal,
        _ => null,
    };
}
