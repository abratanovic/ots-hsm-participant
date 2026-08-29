namespace MedSign.Api.Passkeys;

public sealed record RelyingParty(string Id, string Name);

public sealed record PasskeyUser(string Id, string Name, string DisplayName);

public sealed record PasskeyAlgorithm(string Type, int Alg);

public sealed record AuthenticatorSelection(string ResidentKey, string UserVerification);

public sealed record PasskeyDescriptor(string Id, IReadOnlyList<string>? Transports);
