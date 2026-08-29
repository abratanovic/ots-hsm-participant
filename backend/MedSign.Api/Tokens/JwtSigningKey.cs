using MedSign.Api.Shared;

namespace MedSign.Api.Tokens;

public sealed class JwtSigningKey
{
    public int Id { get; init; }

    public required string Provider { get; init; }

    public required string Label { get; init; }

    public required byte[] EcPoint { get; init; }

    public required string Kid { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }
}
