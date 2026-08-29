using MedSign.Api.Shared;

namespace MedSign.Api.Hsm;

/// <summary>
/// A report a doctor issued: what it says, who it is about, and the signed PDF
/// it produced.
///
/// The row and the file are two halves of one thing. What was signed is the
/// SHA-256 of the file's bytes, not a serialisation of these columns, so the
/// PDF is the authoritative artifact and this is the index over it. Nothing
/// here may be edited after the fact -- a changed column would not invalidate
/// the signature, which is exactly why the application never offers to change
/// one.
///
/// There is no unsigned state. <see cref="Signature"/> and
/// <see cref="SigningKeyId"/> are required because a report that exists without
/// them is not something this system permits, and a nullable column is an
/// invitation to produce one.
/// </summary>
public sealed class MedicalReport
{
    /// <summary>
    /// The longest body MedSign will render. Long enough for any real set of
    /// findings, short enough that a document stays a document.
    /// </summary>
    public const int MaxBodyLength = 10_000;

    public int Id { get; init; }

    /// <summary>
    /// The API's <c>id</c> and the PDF's filename stem, doing double duty so
    /// there is one identifier rather than two. A guid rather than the
    /// surrogate key: report URLs and file paths are then not enumerable and
    /// say nothing about how many reports exist.
    /// </summary>
    public required Guid PublicId { get; init; }

    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>One of <see cref="ReportTypes"/>.</summary>
    public required string Type { get; init; }

    /// <summary>The doctor's findings, plain text.</summary>
    public required string Body { get; init; }

    public required int DoctorUserId { get; init; }

    public User Doctor { get; init; } = null!;

    public required int PatientUserId { get; init; }

    public User Patient { get; init; } = null!;

    /// <summary>
    /// What a download is called. Deliberately not the storage name: the file
    /// on disk is named by the public id so paths leak nothing, and a patient
    /// saving their record should still get something they can recognise later.
    /// </summary>
    public required string FileName { get; init; }

    public required long FileSizeBytes { get; init; }

    /// <summary>Lowercase hex digest of the file. What was signed.</summary>
    public required string Sha256 { get; init; }

    /// <summary>Raw R||S, 64 bytes -- what the device returns, undecorated.</summary>
    public required byte[] Signature { get; init; }

    /// <summary>
    /// The key that signed this report, not merely the doctor who owns it. The
    /// one concession to a future in which keys rotate: without it, history
    /// becomes unverifiable the moment a doctor's key situation changes.
    /// </summary>
    public required int SigningKeyId { get; init; }

    public SigningKey SigningKey { get; init; } = null!;
}

/// <summary>
/// The four kinds of record a doctor can issue, kebab-case on the wire because
/// that is what the frontend's type union already says.
/// </summary>
public static class ReportTypes
{
    public const string Findings = "findings";
    public const string DischargeSummary = "discharge-summary";
    public const string Referral = "referral";
    public const string Certificate = "certificate";

    public static readonly string[] All = [Findings, DischargeSummary, Referral, Certificate];

    public static bool IsKnown(string? type) => All.Contains(type, StringComparer.Ordinal);

    /// <summary>The heading a person reads on the rendered document.</summary>
    public static string Describe(string type) => type switch
    {
        Findings => "Findings",
        DischargeSummary => "Discharge summary",
        Referral => "Referral",
        Certificate => "Certificate",
        _ => type,
    };
}
