using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;

namespace MedSign.Api.Hsm;

public static class ReportEndpoints
{
    public static void MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/reports");

        // The whole act in one call, because attesting to a document is one
        // act: MedSign records the report, renders it, signs the file's digest
        // on the device, and hands the finished thing back. There is no
        // separate "now sign it" step to forget or to fail on its own.
        group.MapPost("", (HttpContext context, IssueReport request, ReportIssuing reports) =>
            Results.Ok(ReportView.Of(reports.Issue(context.Session().UserId, request))))
            .RequireRole(Roles.Doctor)
            .WithName("IssueReport");
    }
}

/// <summary>
/// A report as the API describes it.
///
/// The nesting is the point. <see cref="Document"/> and <see cref="Signature"/>
/// are separate objects that name each other through the digest: the signature
/// was computed over that hash, and verification is the question of whether the
/// stored file still produces it. Flattening them would make a report look like
/// a record that happens to carry signature fields, which is the wrong way
/// round.
/// </summary>
public sealed record ReportView(
    Guid Id,
    PartyView Patient,
    PartyView Doctor,
    string Type,
    DateTimeOffset IssuedAt,
    string Body,
    DocumentView Document,
    SignatureView Signature)
{
    public static ReportView Of(MedicalReport report) => new(
        report.PublicId,
        PartyView.Of(report.Patient),
        PartyView.Of(report.Doctor),
        report.Type,
        report.IssuedAt,
        report.Body,
        DocumentView.Of(report),
        SignatureView.Of(report));
}

/// <summary>
/// One side of a report, as MedSign knows them. Read from the account, never
/// from the request that issued the report.
/// </summary>
public sealed record PartyView(int Id, string Username, string Name)
{
    public static PartyView Of(User user) => new(user.Id, user.Username, user.DisplayName);
}

/// <summary>The stored PDF: what was signed, and what a download hands over.</summary>
public sealed record DocumentView(string FileName, long SizeBytes, string Sha256)
{
    public static DocumentView Of(MedicalReport report) =>
        new(report.FileName, report.FileSizeBytes, report.Sha256);
}

/// <summary>
/// The detached signature over the document's digest.
///
/// Detached: the PDF itself is untouched and carries no signature dictionary,
/// so it will not show as signed in a PDF reader. The bytes live here instead,
/// and MedSign is what checks them.
/// </summary>
public sealed record SignatureView(string Algorithm, string KeyId, string Value)
{
    /// <summary>
    /// ECDSA on P-256 over a SHA-256 digest -- the same curve and the same name
    /// the session tokens use, because it is the same device doing it.
    /// </summary>
    public const string Es256 = "ES256";

    /// <summary>
    /// The key is named by its label, which is the handle that lasts: a PKCS#11
    /// object handle does not survive the device's session being reset.
    /// </summary>
    public static SignatureView Of(MedicalReport report) => new(
        Es256, report.SigningKey.KeyLabel, Base64Url.Encode(report.Signature));
}
