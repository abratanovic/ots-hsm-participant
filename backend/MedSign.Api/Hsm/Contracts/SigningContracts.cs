using MedSign.Api.Hsm.Device;

namespace MedSign.Api.Hsm.Contracts;

public sealed record SigningStatus(
    bool Enabled,
    string? PublicKeyFingerprint = null,
    DateTimeOffset? CreatedAt = null)
{
    public static SigningStatus Of(SigningKey? key) => key is null
        ? new SigningStatus(false)
        : new SigningStatus(
            true,
            SigningKey.Fingerprint(key.PublicKeyPoint),
            key.CreatedAt);
}
