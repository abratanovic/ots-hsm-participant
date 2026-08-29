using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm;

/// <summary>
/// Issuing a report: recording it, rendering it, hashing the file and having
/// the device sign that hash with the doctor's own key.
///
/// It is one method because it is one act. Splitting "persist and render" from
/// "sign" would create the state the design forbids -- a report on file that
/// nothing attests to -- so the two cannot be separately callable.
///
/// The order is what makes it atomic, and it is deliberate: everything that can
/// fail happens before the row is written. Rendering, writing the file and
/// signing all come first; <c>SaveChanges</c> is the last thing that happens
/// and is itself the transaction. So a device that cannot sign leaves no row at
/// all, and the file written moments earlier is deleted on the way out.
/// </summary>
public sealed class ReportIssuing(
    MedSignDb db,
    IDocumentSigner signer,
    ReportStorage storage,
    TimeProvider clock,
    ILogger<ReportIssuing> log)
{
    public MedicalReport Issue(int doctorUserId, IssueReport request)
    {
        var type = ReadType(request.Type);
        var body = ReadBody(request.Body);

        var doctor = db.Users
            .Include(user => user.SigningKey)
            .SingleOrDefault(user => user.Id == doctorUserId)
            ?? throw new InvalidOperationException(
                $"There is no account {doctorUserId} to issue a report from.");

        var key = doctor.SigningKey
            ?? throw new InvalidOperationException(
                "Document signing is not enabled for this account, so there is no key to sign a "
                + "report with. Enable signing first: it generates a key for you on the HSM, and "
                + "MedSign does not keep unsigned reports.");

        var patient = ReadPatient(request.PatientId);

        var publicId = Guid.NewGuid();
        var issuedAt = clock.GetUtcNow();

        var pdf = ReportDocument.Render(new ReportContent(
            issuedAt, doctor.DisplayName, patient.DisplayName, ReportTypes.Describe(type), body));

        storage.Write(publicId, pdf);

        try
        {
            var digest = SHA256.HashData(pdf);

            var report = new MedicalReport
            {
                PublicId = publicId,
                IssuedAt = issuedAt,
                Type = type,
                Body = body,
                DoctorUserId = doctor.Id,
                Doctor = doctor,
                PatientUserId = patient.Id,
                Patient = patient,
                FileName = DownloadName.For(type, issuedAt, patient.DisplayName),
                FileSizeBytes = pdf.LongLength,
                Sha256 = Convert.ToHexStringLower(digest),

                // The device, with this doctor's key and nobody else's. Last
                // before the commit, so its failure is the request's failure.
                Signature = signer.SignDigest(key.KeyLabel, digest),
                SigningKeyId = key.Id,
                SigningKey = key,
            };

            db.MedicalReports.Add(report);
            db.SaveChanges();

            return report;
        }
        catch
        {
            Discard(publicId);

            throw;
        }
    }

    /// <summary>
    /// Removes the document written for a report that was never issued.
    ///
    /// Best effort: this runs with the real failure already on its way up, and
    /// a file that will not delete must not replace a "the HSM is down" with an
    /// IO error. Nothing points at the orphan either way.
    /// </summary>
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

    /// <summary>
    /// The account the report is about.
    ///
    /// Only patients, and checked here rather than trusted from the patient
    /// list the frontend picked from: a report filed against a colleague's
    /// account is somebody's findings in the wrong person's record.
    /// </summary>
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

/// <summary>
/// What a doctor supplies. Everything else -- the identifier, the date, both
/// parties' names, the file and the signature -- is MedSign's to derive, which
/// is why a patient is named by account id and not by name.
/// </summary>
public sealed record IssueReport(int PatientId, string? Type, string? Body);

/// <summary>
/// What a download is called.
///
/// Purely cosmetic and deliberately not the storage name: the file on disk is
/// named by the report's public id so a path leaks nothing, while a patient
/// saving their own record gets something they can find again.
/// </summary>
public static class DownloadName
{
    public static string For(string type, DateTimeOffset issuedAt, string patientName) =>
        $"{type}-{issuedAt:yyyy-MM-dd}-{Slug(patientName)}.pdf";

    /// <summary>
    /// A name reduced to what every file system agrees on. Diacritics are
    /// folded rather than dropped, so Kovač stays kovac rather than kova.
    /// </summary>
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
