using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;

namespace MedSign.Api.Hsm.Reports;

public sealed class MedicalReport
{
    public const int MaxBodyLength = 10_000;

    public int Id { get; init; }

    public required Guid PublicId { get; init; }

    public required DateTimeOffset IssuedAt { get; init; }

    public required string Type { get; init; }

    public required string Body { get; init; }

    public required int DoctorUserId { get; init; }

    public User Doctor { get; init; } = null!;

    public required int PatientUserId { get; init; }

    public User Patient { get; init; } = null!;

    public required string FileName { get; init; }

    public required long FileSizeBytes { get; init; }

    public required string Sha256 { get; init; }

    public required byte[] Signature { get; init; }

    public required int SigningKeyId { get; init; }

    public SigningKey SigningKey { get; init; } = null!;
}

public static class ReportTypes
{
    public const string Findings = "findings";
    public const string DischargeSummary = "discharge-summary";
    public const string Referral = "referral";
    public const string Certificate = "certificate";

    public static readonly string[] All = [Findings, DischargeSummary, Referral, Certificate];

    public static bool IsKnown(string? type) => All.Contains(type, StringComparer.Ordinal);

    public static string Describe(string type) => type switch
    {
        Findings => "Findings",
        DischargeSummary => "Discharge summary",
        Referral => "Referral",
        Certificate => "Certificate",
        _ => type,
    };
}
