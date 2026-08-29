using MedSign.Api.Hsm;
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

    /// <summary>
    /// The doctor's document signing key, or null when signing is not enabled.
    ///
    /// Null is the whole enrolment check: there is no separate flag to fall out
    /// of step with the key it describes, and a doctor with no key on the device
    /// has no way to represent a signed report.
    /// </summary>
    public int? SigningKeyId { get; set; }

    public SigningKey? SigningKey { get; set; }
}
