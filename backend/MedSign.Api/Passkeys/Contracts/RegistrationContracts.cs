using MedSign.Api.Auth;

namespace MedSign.Api.Passkeys;

public sealed record AccountDetails(string Username, string FullName, string Role);

public sealed record PasskeyCreationChallenge(
    string Challenge,
    RelyingParty Rp,
    PasskeyUser User,
    IReadOnlyList<PasskeyAlgorithm> PubKeyCredParams,
    int Timeout,
    string Attestation,
    AuthenticatorSelection AuthenticatorSelection,
    IReadOnlyList<PasskeyDescriptor> ExcludeCredentials);

public sealed record PasskeyRegistration(
    string Id,
    string RawId,
    string Type,
    IReadOnlyList<string> Transports,
    PasskeyRegistrationResponse Response);

public sealed record PasskeyRegistrationResponse(string ClientDataJSON, string AttestationObject);

public sealed record RegisterAccountRequest(
    string Username,
    string FullName,
    string Role,
    PasskeyRegistration Credential);
