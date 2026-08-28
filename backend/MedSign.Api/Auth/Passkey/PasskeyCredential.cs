namespace MedSign.Api.Auth.Passkey;

public sealed class PasskeyCredential
{
    public int Id { get; init; }

    public int UserId { get; init; }
    public User User { get; init; } = null!;

    public required byte[] CredentialId { get; init; }

    public required byte[] PublicKeyPoint { get; init; }

    public required long SignCount { get; set; }

    public required string Transports { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}
