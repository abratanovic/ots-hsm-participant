using MedSign.Api.Hsm.Device;
using MedSign.Api.Passkeys;

namespace MedSign.Api.Shared;

public sealed class User
{
    public int Id { get; init; }

    public required string Username { get; init; }

    public required byte[] Handle { get; init; }

    public required string DisplayName { get; init; }

    public required string Role { get; init; }

    public List<PasskeyCredential> Credentials { get; init; } = [];

    public int? SigningKeyId { get; set; }

    public SigningKey? SigningKey { get; set; }
}
