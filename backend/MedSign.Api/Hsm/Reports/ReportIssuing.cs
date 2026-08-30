using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using MedSign.Api.Hsm.Contracts;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm.Reports;

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
