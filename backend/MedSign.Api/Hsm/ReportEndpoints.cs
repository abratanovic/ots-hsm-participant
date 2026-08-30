using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;

namespace MedSign.Api.Hsm;

public static class ReportEndpoints
{
    public static void MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/reports");

        group.MapPost("", (HttpContext context, IssueReport request, ReportIssuing reports) =>
            Results.Ok(ReportView.Of(reports.Issue(context.Session().UserId, request))))
            .RequireRole(Roles.Doctor)
            .WithName("IssueReport");

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

        group.MapGet("/{id:guid}/document", async (HttpContext context, Guid id,
                ReportAccess reports, CancellationToken cancellationToken) =>
        {
            var document = await reports.DownloadAsync(context.Session(), id, cancellationToken);

            return Results.File(document.Content, ReportFile.ContentType, document.Name);
        })
            .RequireRole(Roles.Doctor, Roles.Patient)
            .WithName("DownloadReportDocument");

        group.MapGet("/{id:guid}/verification", async (HttpContext context, Guid id,
                ReportVerification verification, CancellationToken cancellationToken) =>
            Results.Ok(await verification.CheckAsync(context.Session(), id, cancellationToken)))
            .RequireRole(Roles.Doctor, Roles.Patient)
            .WithName("VerifyReport");
    }
}

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

public static class ReportExcerpt
{
    public const int MaxLength = 160;

    public const string Ellipsis = "…";

    public static string Of(string body)
    {
        var flattened = string.Join(' ', body.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

        if (flattened.Length <= MaxLength)
        {
            return flattened;
        }

        var cut = flattened[..MaxLength];
        var lastSpace = cut.LastIndexOf(' ');

        return (lastSpace > 0 ? cut[..lastSpace] : cut).TrimEnd() + Ellipsis;
    }
}

public sealed record PartyView(int Id, string Username, string Name)
{
    public static PartyView Of(User user) => new(user.Id, user.Username, user.DisplayName);
}

public sealed record DocumentView(string FileName, long SizeBytes, string Sha256)
{
    public static DocumentView Of(MedicalReport report) =>
        new(report.FileName, report.FileSizeBytes, report.Sha256);
}

public sealed record SignatureView(string Algorithm, string Value)
{
    public const string Es256 = "ES256";

    public static SignatureView Of(MedicalReport report) => new(
        Es256, Base64Url.Encode(report.Signature));
}
