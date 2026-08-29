using System.Linq.Expressions;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm;

/// <summary>
/// Which reports a caller may see, and what they get when they ask for one
/// they may not.
///
/// Everything reads through <see cref="PartyTo"/>, and that is the whole
/// design. A doctor's list and a patient's list are the same query with a
/// different predicate, chosen from the session rather than from anything the
/// client sends -- so there is no parameter to tamper with, and no way for the
/// two lists to drift apart as the feature grows. The single-report lookups
/// apply the same predicate, which is why "not yours" and "no such report"
/// cannot diverge: they are the same empty result.
/// </summary>
public sealed class ReportAccess(MedSignDb db, ReportStorage storage)
{
    /// <summary>
    /// The caller's reports, newest first and unpaginated.
    ///
    /// Ordered by the surrogate key rather than by <c>IssuedAt</c>, for two
    /// reasons that agree. SQLite cannot sort a DateTimeOffset at all, so
    /// ordering by the timestamp would have to happen in memory over every row.
    /// And the key is already the issue order: a report is written once, at the
    /// moment it is issued, and nothing afterwards may edit or reorder one --
    /// so the key says which is newer, and says it even when two reports share
    /// a tick.
    /// </summary>
    public Task<List<MedicalReport>> ListAsync(
        SessionPrincipal caller, CancellationToken cancellationToken) =>
        Signed(caller)
            .OrderByDescending(report => report.Id)
            .ToListAsync(cancellationToken);

    /// <summary>
    /// One of the caller's reports, or a 404 -- for a report that does not
    /// exist and for one that is somebody else's alike.
    /// </summary>
    public async Task<MedicalReport> FindAsync(
        SessionPrincipal caller, Guid id, CancellationToken cancellationToken) =>
        await Signed(caller).SingleOrDefaultAsync(report => report.PublicId == id, cancellationToken)
        ?? throw NoSuchReport(id);

    /// <summary>
    /// The same report and the same refusal, with the key that signed it left
    /// unattached -- the lookup verification asks with.
    ///
    /// The omission is the point. A report's key is a required relationship, so
    /// including it joins on it, and a report whose key row has gone missing
    /// would not be found at all: MedSign would answer "no such report" about a
    /// report that plainly exists, and about the one situation verification is
    /// specifically supposed to name. Verification looks the key up separately
    /// and calls a missing one an unknown signer.
    /// </summary>
    public async Task<MedicalReport> FindForVerificationAsync(
        SessionPrincipal caller, Guid id, CancellationToken cancellationToken) =>
        await Visible(caller).SingleOrDefaultAsync(report => report.PublicId == id, cancellationToken)
        ?? throw NoSuchReport(id);

    /// <summary>
    /// A report's document, for a party to it: the exact bytes that were
    /// hashed and signed when it was issued.
    ///
    /// Nothing regenerates the file. A second rendering would be
    /// byte-different, so the signature stored beside it would no longer
    /// verify, and a download that quietly did that would hand a patient a
    /// document their own records call a forgery.
    /// </summary>
    public async Task<ReportFile> DownloadAsync(
        SessionPrincipal caller, Guid id, CancellationToken cancellationToken)
    {
        var report = await FindAsync(caller, id, cancellationToken);

        // Gone rather than a conflict: a 409 would say "not in this state" and
        // invite the caller to try again once it is. There is no such state to
        // reach. The bytes that were signed are the only ones whose signature
        // verifies, and nothing can produce them a second time.
        var pdf = storage.TryRead(report.PublicId)
            ?? throw new GoneException("That document is gone",
                $"The PDF for report {report.PublicId} is no longer in storage. It cannot be "
                + "regenerated: a new rendering would be a different file, and the signature held "
                + "with this report would not verify against it.");

        return new ReportFile(report.FileName, pdf);
    }

    /// <summary>The caller's reports, with both parties named on each.</summary>
    private IQueryable<MedicalReport> Visible(SessionPrincipal caller) => db.MedicalReports
        .AsNoTracking()
        .Include(report => report.Doctor)
        .Include(report => report.Patient)
        .Where(PartyTo(caller));

    /// <summary>
    /// The same, with the signing key attached -- what a report on the wire
    /// needs, since every one of them names the key it was signed with.
    /// </summary>
    private IQueryable<MedicalReport> Signed(SessionPrincipal caller) =>
        Visible(caller).Include(report => report.SigningKey);

    /// <summary>
    /// What being party to a report means, by role -- the one place the two
    /// readings of "my reports" are written down.
    ///
    /// An unrecognised role throws rather than defaulting, because every
    /// default here is somebody else's medical records: falling back to the
    /// doctor's predicate would show a stranger a caseload, and falling back to
    /// an empty one would hide a patient's own records from them without
    /// saying so.
    /// </summary>
    private static Expression<Func<MedicalReport, bool>> PartyTo(SessionPrincipal caller) =>
        caller.Role switch
        {
            Roles.Doctor => report => report.DoctorUserId == caller.UserId,
            Roles.Patient => report => report.PatientUserId == caller.UserId,
            _ => throw new InvalidOperationException(
                $"There is no reading of 'my reports' for a {caller.Role}. "
                + $"Reports are listed for {Roles.All}."),
        };

    /// <summary>
    /// The one refusal, worded so it fits both of the situations that produce
    /// it. It says nothing about the report, because in one of those situations
    /// there is a report and the caller must not learn that.
    /// </summary>
    private static NotFoundException NoSuchReport(Guid id) => new(
        "There is no such report",
        $"No report {id} is yours to read. Either it does not exist, or it was not issued by you "
        + "or to you.");
}

/// <summary>
/// A document on its way out: the stored bytes, and the name a person should
/// see them saved under.
///
/// The name is the display name recorded when the report was issued, not the
/// storage name -- the file on disk is called after the public id so a path
/// leaks nothing, while a downloads folder should stay navigable.
/// </summary>
public sealed record ReportFile(string Name, byte[] Content)
{
    public const string ContentType = "application/pdf";
}
