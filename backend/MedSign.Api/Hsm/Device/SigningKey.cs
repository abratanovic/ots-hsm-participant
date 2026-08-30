using System.Security.Cryptography;
using MedSign.Api.Shared;

namespace MedSign.Api.Hsm.Device;

public sealed class SigningKey
{
    public int Id { get; init; }

    public required string KeyLabel { get; init; }

    public required byte[] PublicKeyPoint { get; init; }

    public required DateTimeOffset CreatedAt { get; init; }

    public static string Fingerprint(byte[] publicKeyPoint) =>
        Base64Url.Encode(SHA256.HashData(publicKeyPoint));
}

public static class DoctorKeyLabel
{
    public const string Prefix = "medsign-doctor-";

    public static string For(int doctorUserId) => $"{Prefix}{doctorUserId}";
}
