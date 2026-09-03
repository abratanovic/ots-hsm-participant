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
        // TODO HSM 8/8: Decide which of the five VerificationOutcomes this
        // report deserves, and return it. This is the counterpart of what
        // ReportIssuing recorded, so read Exercise HSM 8/10 first -- everything
        // you check here, issuing had to store.
        //
        // In this order, because each step is meaningless without the one above:
        //
        //   1. storage.TryRead(report.PublicId). Null is FileMissing. The PDF is
        //      not regenerated: a fresh rendering would be different bytes, and
        //      the signature would not verify against it.
        //   2. SHA256.HashData(pdf), and compare Convert.ToHexStringLower(digest)
        //      to report.Sha256 with StringComparison.Ordinal. A mismatch is
        //      FileModified. Note what this catches that the signature check
        //      alone would not: it names the file as the thing that changed.
        //   3. key is null: UnknownSigner. The signature may be perfect, but
        //      there is nothing left to check it against, and "cannot tell" is
        //      not the same answer as "forged".
        //   4. EcPoint.Verifier(key.PublicKeyPoint) gives you an ECDsa over the
        //      65-byte point read off the device in Exercise HSM 3/10. Dispose
        //      it -- `using var`.
        //   5. ecdsa.VerifyHash(digest, report.Signature,
        //      DSASignatureFormat.IeeeP1363FixedFieldConcatenation) -> Valid or
        //      SignatureInvalid. That format is not optional: the HSM returns
        //      the raw r||s pair, and .NET's default expectation is DER. Pass
        //      the wrong one and every genuine signature reads as a forgery.
        //
        // Verify the hash, not the document: VerifyHash takes the 32 bytes the
        // device signed. VerifyData would hash it again and check a signature
        // over a hash of a hash.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Reports/ReportVerification.cs#L30-L60
        throw new NotImplementedException(
            "Exercise HSM 9/10: decide the outcome in ReportVerification.Check.");
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
