using System.Security.Cryptography;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm;

/// <summary>
/// The question the whole feature exists to answer: did this doctor sign this
/// document, and has anything changed since.
///
/// Every call re-reads the file from disk and re-runs the arithmetic. Nothing
/// is cached and nothing may be, because what is being asserted is not a fact
/// about the past -- it is a fact about the file as it is at this instant, and a
/// remembered answer would describe a file that may since have been edited or
/// deleted.
///
/// Nothing here writes. In particular nothing re-renders a missing PDF: a
/// second rendering is byte-different, so its digest would not match the
/// signature, and a verifier that quietly regenerated its own subject would
/// destroy the claim it was asked to check.
/// </summary>
public sealed class ReportVerification(
    MedSignDb db, ReportAccess reports, ReportStorage storage, TimeProvider clock)
{
    public async Task<VerificationView> CheckAsync(
        SessionPrincipal caller, Guid id, CancellationToken cancellationToken)
    {
        // The same party check the other single-report routes apply, so a
        // stranger gets the same 404 here as everywhere else and cannot learn
        // from a verification that a report exists.
        var report = await reports.FindAsync(caller, id, cancellationToken);

        // Looked up by id rather than read off the report's navigation: a key
        // row that has gone missing is an outcome this method reports, not a
        // reason for the report itself to disappear from the query.
        var key = await db.SigningKeys
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.Id == report.SigningKeyId, cancellationToken);

        return new VerificationView(
            report.PublicId,
            Check(report, key),
            clock.GetUtcNow(),
            SignatureView.Es256,
            PartyView.Of(report.Doctor));
    }

    /// <summary>
    /// Which of the five things is true, asked in the order that keeps each
    /// answer honest.
    ///
    /// The file comes first, because the two questions about it -- is it there,
    /// is it the file that was signed -- are answered against the recorded
    /// digest and need no key at all. Only then does the signer matter, so an
    /// operational problem is never reported as a forgery and a key MedSign has
    /// lost is never reported as a doctor's signature failing to check out.
    /// </summary>
    private string Check(MedicalReport report, SigningKey? key)
    {
        var pdf = storage.TryRead(report.PublicId);

        if (pdf is null)
        {
            return VerificationOutcomes.FileMissing;
        }

        var digest = SHA256.HashData(pdf);

        if (!Convert.ToHexStringLower(digest).Equals(report.Sha256, StringComparison.Ordinal))
        {
            return VerificationOutcomes.FileModified;
        }

        if (key is null)
        {
            return VerificationOutcomes.UnknownSigner;
        }

        using var ecdsa = EcPoint.Verifier(key.PublicKeyPoint);

        // Raw R||S against the stored point, the same fixed-field concatenation
        // the session tokens are checked with -- it is the same device, the same
        // curve and the same encoding, so it is the same call.
        return ecdsa.VerifyHash(digest, report.Signature,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
            ? VerificationOutcomes.Valid
            : VerificationOutcomes.SignatureInvalid;
    }
}

/// <summary>
/// What MedSign can truthfully say about a report's signature.
///
/// Five values rather than a boolean, because the situations behind them are
/// not the same situation and a person acts differently on each: a modified
/// file is tampering, a missing file is an operations problem, an unknown
/// signer is MedSign's own record-keeping, and only one of them says the
/// document is not what it claims to be.
///
/// Kebab-case on the wire, matching the report types and the frontend's union.
/// </summary>
public static class VerificationOutcomes
{
    /// <summary>The stored file hashes as recorded, and the signature checks out against the key.</summary>
    public const string Valid = "valid";

    /// <summary>There is no file at the report's path. Not a forgery -- an absence.</summary>
    public const string FileMissing = "file-missing";

    /// <summary>The file is there, and its bytes are no longer the bytes that were signed.</summary>
    public const string FileModified = "file-modified";

    /// <summary>The right file, and a signature over it that this key did not produce.</summary>
    public const string SignatureInvalid = "signature-invalid";

    /// <summary>The key this report was signed with is no longer on file, so nothing can be checked.</summary>
    public const string UnknownSigner = "unknown-signer";
}

/// <summary>
/// The answer, and who it is about.
///
/// It names the doctor rather than returning a bare verdict, because "valid"
/// alone is a claim about nothing in particular: what a patient wants to know
/// is that <em>this named doctor</em> signed it, with a key MedSign holds for
/// them. Which key that is stays inside MedSign -- the answer is about a
/// person, and the label the device knows the key by tells a reader nothing
/// they can act on.
///
/// <see cref="CheckedAt"/> is on every answer for the same reason nothing is
/// cached -- it is true of the file at that moment and says so.
/// </summary>
public sealed record VerificationView(
    Guid ReportId,
    string Outcome,
    DateTimeOffset CheckedAt,
    string Algorithm,
    PartyView Doctor);
