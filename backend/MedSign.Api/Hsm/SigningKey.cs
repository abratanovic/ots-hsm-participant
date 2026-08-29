using System.Security.Cryptography;
using MedSign.Api.Shared;

namespace MedSign.Api.Hsm;

/// <summary>
/// A document signing key that belongs to one doctor: the label the device
/// knows it by, and the public half.
///
/// The private half is not here and has no column, because it is not anywhere
/// MedSign can reach -- it was generated inside the YubiHSM marked
/// non-exportable and there is no operation that would get it out.
///
/// Distinct from <see cref="JwtSigningKey"/>, which is the one application-wide
/// key MedSign signs its own session tokens with. Both live in the same token
/// on the same device; only the label tells them apart.
/// </summary>
public sealed class SigningKey
{
    public int Id { get; init; }

    /// <summary>
    /// What the device knows this key by, and the only handle on it that lasts.
    /// A PKCS#11 object handle does not survive the session being reset; a label
    /// does, which is why the communicator looks keys up by one on every call.
    /// </summary>
    public required string KeyLabel { get; init; }

    public required byte[] PublicKeyPoint { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// A short name for the public key, derived the same way the JWT key's kid
    /// is: SHA-256 over the point. Two doctors cannot share one, and it says
    /// nothing a reader of the public key does not already know.
    /// </summary>
    public static string Fingerprint(byte[] publicKeyPoint) =>
        Base64Url.Encode(SHA256.HashData(publicKeyPoint));
}

/// <summary>
/// Which key on the device belongs to which doctor.
///
/// Derived from the account id rather than stored, so it is the same label
/// every time and cannot drift from the account it names. The prefix is what
/// keeps a doctor's key from colliding with the application's own signing key
/// in the same token -- <see cref="DoctorSigningKeys"/> checks that too, since
/// the JWT label is configurable and a workshop is exactly where somebody sets
/// it to something unfortunate.
/// </summary>
public static class DoctorKeyLabel
{
    public const string Prefix = "medsign-doctor-";

    public static string For(int doctorUserId) => $"{Prefix}{doctorUserId}";
}
