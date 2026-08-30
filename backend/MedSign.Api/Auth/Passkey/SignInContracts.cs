namespace MedSign.Api.Auth.Passkey;

public sealed record PasskeyChallengeRequest(string Username);

public sealed record PasskeyChallenge(
    string Challenge,
    string RpId,
    int Timeout,
    string UserVerification,
    IReadOnlyList<PasskeyDescriptor>? AllowCredentials);

public sealed record PasskeyAssertion(
    string Id,
    string RawId,
    string Type,
    PasskeyAssertionResponse Response);

public sealed record PasskeyAssertionResponse(
    string ClientDataJSON,
    string AuthenticatorData,
    string Signature,
    string? UserHandle);

public sealed record SignInRequest(string Username, PasskeyAssertion Assertion);
