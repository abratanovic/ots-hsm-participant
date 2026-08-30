using System.Security.Cryptography;
using MedSign.Api.Hsm.Contracts;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm.Reports;

public sealed class ReportVerification(
    MedSignDb db, ReportAccess reports, ReportStorage storage, TimeProvider clock)
{
    public async Task<VerificationView> CheckAsync(
        SessionPrincipal caller, Guid id, CancellationToken cancellationToken)
    {
        var report = await reports.FindAsync(caller, id, cancellationToken);

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

        return ecdsa.VerifyHash(digest, report.Signature,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
            ? VerificationOutcomes.Valid
            : VerificationOutcomes.SignatureInvalid;
    }
}

public static class VerificationOutcomes
{
    public const string Valid = "valid";

    public const string FileMissing = "file-missing";

    public const string FileModified = "file-modified";

    public const string SignatureInvalid = "signature-invalid";

    public const string UnknownSigner = "unknown-signer";
}
