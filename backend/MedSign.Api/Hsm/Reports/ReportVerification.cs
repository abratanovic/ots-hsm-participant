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
        // TODO HSM 10/10: Answer this caller's question about report {id}.
        //
        // Find the report through reports.FindAsync(caller, id, ...) rather than
        // querying db yourself. That method is what makes a report invisible to
        // anyone who is not its doctor or its patient, and it answers a stranger
        // with "no such report" rather than "not yours" -- which is a decision
        // about what a 404 is allowed to leak, not a convenience.
        //
        // Load the SigningKey row whose Id is report.SigningKeyId, AsNoTracking,
        // and let it be null: the key may have been deleted since. Hand both to
        // Check() and wrap the answer in a VerificationView with the report's
        // PublicId, clock.GetUtcNow(), SignatureView.Es256, and
        // PartyView.Of(report.Doctor).
        //
        // Nothing here may throw for a bad signature. An unverifiable report is
        // a 200 carrying a verdict; the exceptions belong to FindAsync, for
        // reports this caller may not see at all.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Reports/ReportVerification.cs#L13-L28
        throw new NotImplementedException(
            "Exercise HSM 10/10: assemble the verification answer in ReportVerification.CheckAsync.");
    }

    private string Check(MedicalReport report, SigningKey? key)
    {
        // TODO HSM 9/10: Decide which of the five VerificationOutcomes this
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
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Reports/ReportVerification.cs#L30-L57
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
