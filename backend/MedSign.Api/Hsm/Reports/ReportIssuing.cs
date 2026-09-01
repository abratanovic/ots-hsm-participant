using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MedSign.Api.Hsm.Contracts;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm.Reports;

// Where the device work in Hsm/Device becomes a signed document. HsmCommunicator
// taught the token to hold a key and sign 32 bytes with it; this class decides
// which 32 bytes, and what has to be true of the row it stores beside them.
//
// The contract is not written here -- it is written in ReportVerification.Check,
// Exercise HSM 9/10, which reads back everything this method stores. The two
// have to agree exactly, so read that exercise alongside this one. Anything
// Issue records that Check cannot reproduce comes back as file-modified or
// signature-invalid, and it comes back that way for every report ever issued,
// not just the next one.
public sealed class ReportIssuing(
    MedSignDb db,
    IDocumentSigner signer,
    ReportStorage storage,
    TimeProvider clock,
    ILogger<ReportIssuing> log)
{
    public MedicalReport Issue(int doctorUserId, IssueReport request)
    {
        // TODO HSM 7/8: Render the report to a PDF, sign it on the HSM, and
        // store the row that lets anyone verify it later.
        //
        // Validate first, with the Read* helpers below: ReadType(request.Type),
        // ReadBody(request.Body), ReadPatient(request.PatientId). Load the
        // doctor from db.Users with .Include(user => user.SigningKey) -- one
        // query, because you need the key, not just the id -- and refuse the
        // request when that key is null: signing is not enabled for the account,
        // and MedSign does not keep unsigned reports.
        //
        // Then, in this order, and the order is the exercise:
        //
        //   1. Mint a Guid publicId and take clock.GetUtcNow() once. Both go in
        //      the PDF and in the row, so they have to be the same values in
        //      both.
        //   2. ReportDocument.Render(new ReportContent(...)) -- the exact bytes
        //      you are about to sign. Render once and keep the array; rendering
        //      twice is not guaranteed to give you the same bytes, and then the
        //      signature covers a document nobody has.
        //   3. storage.Write(publicId, pdf).
        //   4. SHA256.HashData(pdf). You sign the digest, not the document: the
        //      HSM round-trips 32 bytes, not a megabyte of PDF.
        //   5. Build the MedicalReport. Sha256 is Convert.ToHexStringLower(digest)
        //      -- Check compares that string literally. Signature is
        //      signer.SignDigest(key.KeyLabel, digest), the raw r||s pair from
        //      Exercise HSM 6/10, which is what Check hands to VerifyHash as
        //      IeeeP1363FixedFieldConcatenation. Record SigningKeyId too: a
        //      signature nobody can attribute to a key verifies as
        //      unknown-signer. FileName comes from DownloadName.For(...) and
        //      FileSizeBytes from the rendered array.
        //   6. db.MedicalReports.Add(report), db.SaveChanges(), return it.
        //
        // Steps 3 to 6 are two stores that have to agree -- a file on disk and a
        // row in the database -- and only one of them is transactional. Wrap
        // them so that any failure after the write calls Discard(publicId) and
        // rethrows. A PDF on disk with no row referencing it is a leak nobody
        // will ever notice; get the ordering wrong the other way and you have a
        // row pointing at a file that was never written.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Reports/ReportIssuing.cs#L18-L79
        throw new NotImplementedException(
            "Exercise HSM 8/10: sign and store the report in ReportIssuing.Issue.");
    }

    private void Discard(Guid publicId)
    {
        try
        {
            storage.Discard(publicId);
        }
        catch (IOException failure)
        {
            log.LogWarning(failure,
                "Issuing report {PublicId} failed and its PDF could not be deleted. "
                + "No row references it; remove {Path} by hand.",
                publicId, storage.PathFor(publicId));
        }
    }

    private static string ReadType(string? type) => ReportTypes.IsKnown(type)
        ? type!
        : throw new BadRequestException("That is not a kind of report",
            $"'{type ?? "(none)"}' is not a report type. It has to be one of "
            + $"{string.Join(", ", ReportTypes.All)}.");

    private static string ReadBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            throw new BadRequestException("A report needs findings",
                "The report body is empty. A signed document that says nothing is still a signed "
                + "document, so MedSign will not issue one.");
        }

        var trimmed = body.Trim();

        return trimmed.Length <= MedicalReport.MaxBodyLength
            ? trimmed
            : throw new BadRequestException("That report is too long",
                $"The body is {trimmed.Length.ToString("N0", CultureInfo.InvariantCulture)} "
                + $"characters; the limit is "
                + $"{MedicalReport.MaxBodyLength.ToString("N0", CultureInfo.InvariantCulture)}.");
    }

    private User ReadPatient(int patientId)
    {
        var patient = db.Users.SingleOrDefault(user => user.Id == patientId)
            ?? throw new BadRequestException("There is no such patient",
                $"No account {patientId} exists, so there is nobody to issue this report to.");

        return patient.Role == Roles.Patient
            ? patient
            : throw new BadRequestException("That account is not a patient",
                $"{patient.DisplayName} is signed up as a {patient.Role}. Reports are issued to "
                + "patients.");
    }
}

public static class DownloadName
{
    public static string For(string type, DateTimeOffset issuedAt, string patientName) =>
        $"{type}-{issuedAt:yyyy-MM-dd}-{Slug(patientName)}.pdf";

    private static string Slug(string name)
    {
        var folded = new StringBuilder();

        foreach (var character in name.Normalize(NormalizationForm.FormD))
        {
            if (CharUnicodeInfo.GetUnicodeCategory(character) == UnicodeCategory.NonSpacingMark)
            {
                continue;
            }

            folded.Append(char.IsAsciiLetterOrDigit(character) ? char.ToLowerInvariant(character) : '-');
        }

        var slug = string.Join('-', folded.ToString().Split('-', StringSplitOptions.RemoveEmptyEntries));

        return slug.Length > 0 ? slug : "report";
    }
}
