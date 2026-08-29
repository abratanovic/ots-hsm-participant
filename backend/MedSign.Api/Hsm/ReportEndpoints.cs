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

        // One route, two meanings, and the session picks which: reports this
        // doctor issued, or reports issued to this patient. Not a query
        // parameter -- a client that can name whose reports it wants is a
        // client that can name somebody else's.
        group.MapGet("", async (HttpContext context, ReportAccess reports,
                CancellationToken cancellationToken) =>
            Results.Ok((await reports.ListAsync(context.Session(), cancellationToken))
                .Select(ReportSummaryView.Of)
                .ToList()))
            .RequireRole(Roles.Doctor, Roles.Patient)
            .WithName("ListReports");

        group.MapGet("/{id:guid}", async (HttpContext context, Guid id, ReportAccess reports,
                CancellationToken cancellationToken) =>
            Results.Ok(ReportView.Of(await reports.FindAsync(context.Session(), id, cancellationToken))))
            .RequireRole(Roles.Doctor, Roles.Patient)
            .WithName("GetReport");

        // The file itself, behind the same session and the same party check as
        // everything else. A report URL that is guessable would otherwise be a
        // way to read somebody's records without an account at all.
        group.MapGet("/{id:guid}/document", async (HttpContext context, Guid id,
                ReportAccess reports, CancellationToken cancellationToken) =>
        {
            var document = await reports.DownloadAsync(context.Session(), id, cancellationToken);

            return Results.File(document.Content, ReportFile.ContentType, document.Name);
        })
            .RequireRole(Roles.Doctor, Roles.Patient)
            .WithName("DownloadReportDocument");

        // A GET, because asking whether a document is genuine changes nothing
        // about it -- and 200 whatever the answer, including "this is not
        // genuine". That is a successful answer to the question asked; a 4xx
        // would mean the question could not be asked at all.
        group.MapGet("/{id:guid}/verification", async (HttpContext context, Guid id,
                ReportVerification verification, CancellationToken cancellationToken) =>
            Results.Ok(await verification.CheckAsync(context.Session(), id, cancellationToken)))
            .RequireRole(Roles.Doctor, Roles.Patient)
            .WithName("VerifyReport");
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
/// A report in a list: <see cref="ReportView"/> with the body replaced by an
/// excerpt of it.
///
/// The same shape otherwise, down to the nesting, so the frontend renders a
/// list entry and an opened report with the same understanding of what a report
/// is. Both parties are named on every entry rather than just the counterparty,
/// because the counterparty depends on who is looking and a payload that
/// changes its meaning by caller is a payload nothing can be written against.
/// </summary>
public sealed record ReportSummaryView(
    Guid Id,
    PartyView Patient,
    PartyView Doctor,
    string Type,
    DateTimeOffset IssuedAt,
    string Excerpt,
    DocumentView Document,
    SignatureView Signature)
{
    public static ReportSummaryView Of(MedicalReport report) => new(
        report.PublicId,
        PartyView.Of(report.Patient),
        PartyView.Of(report.Doctor),
        report.Type,
        report.IssuedAt,
        ReportExcerpt.Of(report.Body),
        DocumentView.Of(report),
        SignatureView.Of(report));
}

/// <summary>
/// The first line or so of a report's findings.
///
/// A list of a hundred reports should not be a hundred whole documents on the
/// wire, and a list entry is a thing to recognise rather than a thing to read:
/// the full body is one request away, at the report's own URL.
/// </summary>
public static class ReportExcerpt
{
    /// <summary>
    /// About a line and a half of prose -- long enough to tell two reports
    /// apart, short enough that a list stays a list.
    /// </summary>
    public const int MaxLength = 160;

    /// <summary>The character that says the rest of it is elsewhere.</summary>
    public const string Ellipsis = "…";

    public static string Of(string body)
    {
        // Collapsed to one line first: a body is plain text with paragraphs in
        // it, and a list entry has one line to give.
        var flattened = string.Join(' ', body.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

        if (flattened.Length <= MaxLength)
        {
            return flattened;
        }

        var cut = flattened[..MaxLength];
        var lastSpace = cut.LastIndexOf(' ');

        // Cut at a word rather than mid-syllable, unless the body is one long
        // unbroken run and there is no word to cut at.
        return (lastSpace > 0 ? cut[..lastSpace] : cut).TrimEnd() + Ellipsis;
    }
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
