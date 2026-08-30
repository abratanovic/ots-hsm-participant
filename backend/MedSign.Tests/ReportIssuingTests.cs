using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using MedSign.Api.Hsm;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;
using UglyToad.PdfPig;

namespace MedSign.Tests;

/// <summary>
/// POST /api/reports.
///
/// This is where the workshop's claim stops being about keys and becomes
/// something a participant can hold: a doctor writes their findings, MedSign
/// renders a PDF, and the device signs that file's digest with a key belonging
/// to that doctor and to nobody else.
///
/// The act is deliberately indivisible. A report that exists without a
/// signature is not a state this system has, so every test below that makes
/// signing fail asserts on both halves -- no row, and no file.
/// </summary>
public class ReportIssuingTests
{
    private const string Findings = "Blood pressure 128/82. No further action.";

    /// <summary>
    /// A doctor who has already enabled signing, and a patient to write about.
    /// Enrolment goes through the endpoint rather than the database, so these
    /// tests start from a state the application itself produced.
    /// </summary>
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

        // A guid, so a report URL says nothing about how many reports exist.
        Assert.True(Guid.TryParse(answer.Text("id"), out var publicId));
        Assert.NotEqual(Guid.Empty, publicId);

        Assert.Equal(ReportTypes.Findings, answer.Text("type"));
        Assert.Equal(Findings, answer.Text("body"));
        Assert.NotNull(answer.Field("issuedAt"));

        // Both parties by name: a report the frontend cannot attribute to a
        // person is a row of identifiers.
        Assert.Equal("Marko Kovač", answer.Field("patient")?.GetProperty("name").GetString());
        Assert.Equal("Dr. Helena Novak", answer.Field("doctor")?.GetProperty("name").GetString());

        var document = answer.Field("document")!.Value;

        Assert.EndsWith(".pdf", document.GetProperty("fileName").GetString());
        Assert.True(document.GetProperty("sizeBytes").GetInt64() > 0);
        Assert.Matches("^[0-9a-f]{64}$", document.GetProperty("sha256").GetString());

        var signature = answer.Field("signature")!.Value;

        Assert.Equal("ES256", signature.GetProperty("algorithm").GetString());
        Assert.False(string.IsNullOrWhiteSpace(signature.GetProperty("value").GetString()));

        // The key is not named. Its label is how MedSign addresses an object on
        // the device, and a report that carried it would hand every reader the
        // name the device answers to for no purpose the reader has.
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

        // The storage name is the public id; the display name is not, so a
        // download can be called something a person would recognise.
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

        // The end-to-end claim, checked the way a verifier will: the stored
        // signature, the stored public point, the digest of the file on disk.
        // The fake device signs with a genuine P-256 key, so this is the real
        // curve arithmetic rather than a stub agreeing with itself.
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

        // The key, not merely the doctor: a report has to stay verifiable even
        // if that doctor's key situation changes later.
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

        // Read back out of the file rather than trusted from the response: the
        // PDF has to stand on its own once it is away from the application.
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

        // A clear message, not a truncated document: the doctor finds out now
        // rather than by reading a report that stops mid-sentence.
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

            // What the frontend used to send. A report is about a person who
            // holds an account, not about a name somebody typed into a form.
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

        // A colleague's account is a real user and still not a recipient:
        // filing findings against another doctor is the mistake this prevents.
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

        // Not a generic failure: there is one specific thing this doctor has
        // to do first, and the response is where they find that out.
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

        // Enrolment already succeeded, so this fails at the signing step --
        // after the PDF has been rendered and written to disk.
        owned.Hsm.Unavailable = true;

        var answer = await clinic.IssueAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, answer.Status);
        Assert.Equal(Problem.ContentType, answer.ContentType);

        // Both halves. An unsigned report is not a state this system has, and
        // an orphaned PDF nothing points at is not one either.
        Assert.Equal(0, owned.Read(db => db.MedicalReports.Count()));
        Assert.Empty(Documents(owned));

        // And the failure is not terminal: the doctor tries again once the
        // device is back.
        owned.Hsm.Unavailable = false;

        Assert.Equal(HttpStatusCode.OK, (await clinic.IssueAsync()).Status);
        Assert.Single(Documents(owned));
    }

    /// <summary>Every PDF this host has written, however it came to be there.</summary>
    private static IReadOnlyList<string> Documents(MedSignHost host)
    {
        var reports = Path.Combine(host.StorageRoot, ReportStorage.Reports);

        return Directory.Exists(reports) ? Directory.GetFiles(reports) : [];
    }
}

/// <summary>
/// The words on the page.
///
/// The rendered document is the artifact that is signed and the thing a patient
/// keeps, so "does it say who issued it" is a question worth asking of the file
/// rather than of the code that wrote it. Reading text back out means a real
/// PDF parser; the alternative was to assert nothing about the page at all.
/// </summary>
internal static class PdfWords
{
    public static string In(byte[] pdf)
    {
        using var document = PdfDocument.Open(pdf);

        return string.Join('\n', document.GetPages().Select(page => page.Text));
    }
}
