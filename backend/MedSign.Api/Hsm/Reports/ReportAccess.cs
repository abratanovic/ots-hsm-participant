using System.Linq.Expressions;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm.Reports;

public sealed class ReportAccess(MedSignDb db, ReportStorage storage)
{
    public Task<List<MedicalReport>> ListAsync(
        SessionPrincipal caller, CancellationToken cancellationToken) =>
        Visible(caller)
            .OrderByDescending(report => report.Id)
            .ToListAsync(cancellationToken);

    public async Task<MedicalReport> FindAsync(
        SessionPrincipal caller, Guid id, CancellationToken cancellationToken) =>
        await Visible(caller).SingleOrDefaultAsync(report => report.PublicId == id, cancellationToken)
        ?? throw NoSuchReport(id);

    public async Task<ReportFile> DownloadAsync(
        SessionPrincipal caller, Guid id, CancellationToken cancellationToken)
    {
        var report = await FindAsync(caller, id, cancellationToken);

        var pdf = storage.TryRead(report.PublicId)
            ?? throw new GoneException("That document is gone",
                $"The PDF for report {report.PublicId} is no longer in storage. It cannot be "
                + "regenerated: a new rendering would be a different file, and the signature held "
                + "with this report would not verify against it.");

        return new ReportFile(report.FileName, pdf);
    }

    private IQueryable<MedicalReport> Visible(SessionPrincipal caller) => db.MedicalReports
        .AsNoTracking()
        .Include(report => report.Doctor)
        .Include(report => report.Patient)
        .Where(PartyTo(caller));

    private static Expression<Func<MedicalReport, bool>> PartyTo(SessionPrincipal caller) =>
        caller.Role switch
        {
            Roles.Doctor => report => report.DoctorUserId == caller.UserId,
            Roles.Patient => report => report.PatientUserId == caller.UserId,
            _ => throw new InvalidOperationException(
                $"There is no reading of 'my reports' for a {caller.Role}. "
                + $"Reports are listed for {Roles.All}."),
        };

    private static NotFoundException NoSuchReport(Guid id) => new(
        "There is no such report",
        $"No report {id} is yours to read. Either it does not exist, or it was not issued by you "
        + "or to you.");
}

public sealed record ReportFile(string Name, byte[] Content)
{
    public const string ContentType = "application/pdf";
}
