using MedSign.Api.Auth;

namespace MedSign.Api.Passkeys;

public sealed record VerifiedCredential(byte[] CredentialId, byte[] PublicKeyPoint, uint SignCount);

public sealed record RegisteredPasskey(byte[] UserHandle, VerifiedCredential Credential);

public sealed record VerifiedAssertion(User Account, PasskeyCredential Credential, uint SignCount);
