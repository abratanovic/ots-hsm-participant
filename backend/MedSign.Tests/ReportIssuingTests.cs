using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Hsm.Reports;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;
using UglyToad.PdfPig;

namespace MedSign.Tests;

public class ReportIssuingTests
{
    private const string Findings = "Blood pressure 128/82. No further action.";

    private static async Task<Clinic> ClinicAsync()
    {
        var host = new MedSignHost();
        var doctor = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");
        var patient = host.Account("m.kovac", Roles.Patient, "Marko Kovač");

        var token = host.TokenFor(doctor);
        await host.CreateClient().PostAsync(Api.SigningEnable, token: token);

        return new Clinic(host, doctor, patient, token);
    }

    private sealed record Clinic(MedSignHost Host, User Doctor, User Patient, string Token)
    {
        public object Draft(string? type = null, string? body = null, int? patientId = null) => new
        {
            patientId = patientId ?? Patient.Id,
            type = type ?? ReportTypes.Findings,
            body = body ?? Findings,
        };

        public Task<Answer> IssueAsync(object? draft = null) =>
            Host.CreateClient().PostAsync(Api.Reports, draft ?? Draft(), Token);
    }

    [Fact]
    public async Task Returns_the_whole_report_the_doctor_just_issued()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await clinic.IssueAsync();

        Assert.Equal(HttpStatusCode.OK, answer.Status);

        Assert.True(Guid.TryParse(answer.Text("id"), out var publicId));
        Assert.NotEqual(Guid.Empty, publicId);

        Assert.Equal(ReportTypes.Findings, answer.Text("type"));
        Assert.Equal(Findings, answer.Text("body"));
        Assert.NotNull(answer.Field("issuedAt"));

        Assert.Equal("Marko Kovač", answer.Field("patient")?.GetProperty("name").GetString());
        Assert.Equal("Dr. Helena Novak", answer.Field("doctor")?.GetProperty("name").GetString());

        var document = answer.Field("document")!.Value;

        Assert.EndsWith(".pdf", document.GetProperty("fileName").GetString());
        Assert.True(document.GetProperty("sizeBytes").GetInt64() > 0);
        Assert.Matches("^[0-9a-f]{64}$", document.GetProperty("sha256").GetString());

        var signature = answer.Field("signature")!.Value;

        Assert.Equal("ES256", signature.GetProperty("algorithm").GetString());
        Assert.False(string.IsNullOrWhiteSpace(signature.GetProperty("value").GetString()));

        Assert.False(signature.TryGetProperty("keyId", out _));
        Assert.DoesNotContain(DoctorKeyLabel.For(clinic.Doctor.Id), answer.Raw);
    }

    [Fact]
    public async Task Writes_the_pdf_under_the_public_id_with_the_size_and_hash_it_recorded()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await clinic.IssueAsync();
        var document = answer.Field("document")!.Value;

        var path = owned.DocumentPath(answer.Text("id")!);

        Assert.True(File.Exists(path), $"No PDF at {path}.");

        var stored = File.ReadAllBytes(path);

        Assert.Equal("%PDF"u8.ToArray(), stored[..4]);
        Assert.Equal(stored.LongLength, document.GetProperty("sizeBytes").GetInt64());
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(stored)),
            document.GetProperty("sha256").GetString());

        Assert.NotEqual($"{answer.Text("id")}.pdf", document.GetProperty("fileName").GetString());
        Assert.Contains("kovac", document.GetProperty("fileName").GetString()!);
    }

    [Fact]
    public async Task Signs_the_files_digest_with_the_issuing_doctors_own_key()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await clinic.IssueAsync();

        var report = owned.Read(db => db.MedicalReports.Include(r => r.SigningKey).Single());
        var stored = File.ReadAllBytes(owned.DocumentPath(answer.Text("id")!));

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = EcPoint.X(report.SigningKey.PublicKeyPoint),
                Y = EcPoint.Y(report.SigningKey.PublicKeyPoint),
            },
        });

        Assert.True(ecdsa.VerifyHash(
            SHA256.HashData(stored),
            report.Signature,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        var doctorsKeyId = owned.Read(db => db.Users
            .Single(user => user.Id == clinic.Doctor.Id).SigningKeyId);

        Assert.Equal(doctorsKeyId, report.SigningKeyId);
        Assert.Equal(clinic.Doctor.Id, report.DoctorUserId);
        Assert.Equal(clinic.Patient.Id, report.PatientUserId);
    }

    [Fact]
    public async Task Renders_the_date_the_parties_the_type_and_the_body_into_the_pdf()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await clinic.IssueAsync(
            clinic.Draft(type: ReportTypes.DischargeSummary, body: Findings));

        var text = PdfWords.In(File.ReadAllBytes(owned.DocumentPath(answer.Text("id")!)));

        Assert.Contains("Dr. Helena Novak", text);
        Assert.Contains("Marko Kovač", text);
        Assert.Contains("Discharge summary", text);
        Assert.Contains("Blood pressure 128/82", text);
        Assert.Contains(DateTimeOffset.UtcNow.Year.ToString(CultureInfo.InvariantCulture), text);
    }

    [Theory]
    [InlineData(ReportTypes.Findings)]
    [InlineData(ReportTypes.DischargeSummary)]
    [InlineData(ReportTypes.Referral)]
    [InlineData(ReportTypes.Certificate)]
    public async Task Accepts_each_of_the_four_report_types(string type)
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await clinic.IssueAsync(clinic.Draft(type: type));

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(type, answer.Text("type"));
    }

    [Fact]
    public async Task Refuses_a_type_that_is_not_one_of_the_four()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await clinic.IssueAsync(clinic.Draft(type: "prescription"));

        Assert.Equal(HttpStatusCode.BadRequest, answer.Status);
        Assert.Equal(Problem.ContentType, answer.ContentType);
        Assert.Equal(0, owned.Read(db => db.MedicalReports.Count()));
    }

    [Fact]
    public async Task Refuses_a_body_that_is_over_the_limit_or_empty()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var tooLong = await clinic.IssueAsync(
            clinic.Draft(body: new string('x', MedicalReport.MaxBodyLength + 1)));

        Assert.Equal(HttpStatusCode.BadRequest, tooLong.Status);
        Assert.Equal(Problem.ContentType, tooLong.ContentType);

        Assert.Contains(
            MedicalReport.MaxBodyLength.ToString("N0", CultureInfo.InvariantCulture),
            tooLong.Raw);

        var empty = await clinic.IssueAsync(clinic.Draft(body: "   "));

        Assert.Equal(HttpStatusCode.BadRequest, empty.Status);
        Assert.Equal(0, owned.Read(db => db.MedicalReports.Count()));
        Assert.Empty(Documents(owned));
    }

    [Fact]
    public async Task Accepts_a_body_of_exactly_the_maximum_length()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await clinic.IssueAsync(
            clinic.Draft(body: new string('x', MedicalReport.MaxBodyLength)));

        Assert.Equal(HttpStatusCode.OK, answer.Status);
    }

    [Fact]
    public async Task Derives_the_patients_details_from_their_account_and_not_from_the_request()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var answer = await owned.CreateClient().PostAsync(Api.Reports, new
        {
            patientId = clinic.Patient.Id,
            type = ReportTypes.Findings,
            body = Findings,

            patient = new { name = "Someone Else", dateOfBirth = "1970-01-01" },
        }, clinic.Token);

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal("Marko Kovač", answer.Field("patient")?.GetProperty("name").GetString());
    }

    [Fact]
    public async Task Refuses_a_recipient_who_does_not_exist_or_is_not_a_patient()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        var unknown = await clinic.IssueAsync(clinic.Draft(patientId: 9999));

        Assert.Equal(HttpStatusCode.BadRequest, unknown.Status);
        Assert.Equal(Problem.ContentType, unknown.ContentType);

        var colleague = owned.Account("i.babic", Roles.Doctor, "Dr. Ivan Babić");

        var wrongRole = await clinic.IssueAsync(clinic.Draft(patientId: colleague.Id));

        Assert.Equal(HttpStatusCode.BadRequest, wrongRole.Status);
        Assert.Equal(0, owned.Read(db => db.MedicalReports.Count()));
        Assert.Empty(Documents(owned));
    }

    [Fact]
    public async Task Refuses_a_doctor_who_has_not_enabled_signing_and_says_what_to_do()
    {
        using var host = new MedSignHost();
        var doctor = host.Account("i.babic", Roles.Doctor, "Dr. Ivan Babić");
        var patient = host.Account("m.kovac", Roles.Patient, "Marko Kovač");

        var answer = await host.CreateClient().PostAsync(Api.Reports, new
        {
            patientId = patient.Id,
            type = ReportTypes.Findings,
            body = Findings,
        }, host.TokenFor(doctor));

        Assert.Equal(HttpStatusCode.Conflict, answer.Status);
        Assert.Equal(Problem.ContentType, answer.ContentType);
        Assert.Contains("signing", answer.Raw, StringComparison.OrdinalIgnoreCase);

        Assert.Equal(0, host.Read(db => db.MedicalReports.Count()));
        Assert.Empty(Documents(host));
    }

    [Fact]
    public async Task Refuses_a_patient_issuing_a_report_and_a_caller_with_no_session()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;
        var client = owned.CreateClient();

        var asPatient = await client.PostAsync(
            Api.Reports, clinic.Draft(), owned.TokenFor(clinic.Patient));

        Assert.Equal(HttpStatusCode.Forbidden, asPatient.Status);

        var anonymous = await client.PostAsync(Api.Reports, clinic.Draft());

        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.Status);
        Assert.Equal(0, owned.Read(db => db.MedicalReports.Count()));
        Assert.Empty(Documents(owned));
    }

    [Fact]
    public async Task Leaves_no_row_and_no_file_when_the_device_cannot_sign()
    {
        var clinic = await ClinicAsync();
        using var owned = clinic.Host;

        owned.Hsm.Unavailable = true;

        var answer = await clinic.IssueAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, answer.Status);
        Assert.Equal(Problem.ContentType, answer.ContentType);

        Assert.Equal(0, owned.Read(db => db.MedicalReports.Count()));
        Assert.Empty(Documents(owned));

        owned.Hsm.Unavailable = false;

        Assert.Equal(HttpStatusCode.OK, (await clinic.IssueAsync()).Status);
        Assert.Single(Documents(owned));
    }

    private static IReadOnlyList<string> Documents(MedSignHost host)
    {
        var reports = Path.Combine(host.StorageRoot, ReportStorage.Reports);

        return Directory.Exists(reports) ? Directory.GetFiles(reports) : [];
    }
}

internal static class PdfWords
{
    public static string In(byte[] pdf)
    {
        using var document = PdfDocument.Open(pdf);

        return string.Join('\n', document.GetPages().Select(page => page.Text));
    }
}
