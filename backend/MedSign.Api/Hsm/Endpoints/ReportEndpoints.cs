using MedSign.Api.Hsm.Contracts;
using MedSign.Api.Hsm.Reports;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;

namespace MedSign.Api.Hsm.Endpoints;

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
