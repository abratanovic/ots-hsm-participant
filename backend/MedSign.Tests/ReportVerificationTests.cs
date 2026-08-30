using System.Net;
using System.Security.Cryptography;
using MedSign.Api.Hsm.Contracts;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Hsm.Reports;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Tests;

public class ReportVerificationTests
{
    private static async Task<Case> CaseAsync()
    {
        var host = new MedSignHost();

        var novak = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");
        var babic = host.Account("i.babic", Roles.Doctor, "Dr. Ivan Babić");
        var kovac = host.Account("m.kovac", Roles.Patient, "Marko Kovač");
        var horvat = host.Account("a.horvat", Roles.Patient, "Ana Horvat");

        var doctorToken = host.TokenFor(novak);
        var client = host.CreateClient();

        await client.PostAsync(Api.SigningEnable, token: doctorToken);

        var issued = await client.PostAsync(Api.Reports, new
        {
            patientId = kovac.Id,
            type = ReportTypes.Findings,
            body = "Blood pressure 128/82. No further action.",
        }, doctorToken);

        Assert.Equal(HttpStatusCode.OK, issued.OrSkip().Status);

        return new Case(host, novak, issued.Text("id")!, doctorToken, host.TokenFor(kovac),
            host.TokenFor(babic), host.TokenFor(horvat));
    }

    private sealed record Case(
        MedSignHost Host,
        User Doctor,
        string ReportId,
        string DoctorToken,
        string PatientToken,
        string OtherDoctorToken,
        string OtherPatientToken)
    {
        public string DocumentPath => Host.DocumentPath(ReportId);

        public async Task<Answer> VerifyAsync(string? token = null) =>
            (await Host.CreateClient().AskAsync(Api.Verification(ReportId), token ?? DoctorToken))
            .OrSkip();

        public async Task<string?> OutcomeAsync(string? token = null)
        {
            var answer = await VerifyAsync(token);

            Assert.Equal(HttpStatusCode.OK, answer.Status);

            return answer.Text("outcome");
        }
    }

    [Fact]
    public async Task Says_valid_for_an_untouched_file_and_names_the_doctor_and_the_algorithm()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var answer = await subject.VerifyAsync();

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(VerificationOutcomes.Valid, answer.Text("outcome"));

        Assert.Equal("Dr. Helena Novak", answer.Field("doctor")?.GetProperty("name").GetString());
        Assert.Equal("h.novak", answer.Field("doctor")?.GetProperty("username").GetString());
        Assert.Equal(SignatureView.Es256, answer.Text("algorithm"));

        Assert.DoesNotContain(DoctorKeyLabel.For(subject.Doctor.Id), answer.Raw);

        Assert.True(answer.Field("checkedAt")?.TryGetDateTimeOffset(out _) ?? false,
            $"The answer carries no checkedAt:\n{answer.Raw}");

        Assert.Equal(subject.ReportId, answer.Text("reportId"));
    }

    [Fact]
    public async Task Answers_the_patient_the_report_is_about_as_readily_as_the_doctor()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        Assert.Equal(VerificationOutcomes.Valid, await subject.OutcomeAsync(subject.PatientToken));
        Assert.Equal(VerificationOutcomes.Valid, await subject.OutcomeAsync(subject.DoctorToken));
    }

    [Fact]
    public async Task Says_file_modified_when_the_bytes_on_disk_no_longer_match_the_recorded_hash()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var pdf = await File.ReadAllBytesAsync(
            subject.DocumentPath, TestContext.Current.CancellationToken);

        pdf[^1] ^= 0xFF;

        await File.WriteAllBytesAsync(
            subject.DocumentPath, pdf, TestContext.Current.CancellationToken);

        Assert.Equal(VerificationOutcomes.FileModified, await subject.OutcomeAsync());
    }

    [Fact]
    public async Task Says_file_missing_when_the_document_is_gone_rather_than_calling_it_a_forgery()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        File.Delete(subject.DocumentPath);

        Assert.Equal(VerificationOutcomes.FileMissing, await subject.OutcomeAsync());

        Assert.False(File.Exists(subject.DocumentPath),
            "Verification regenerated the document it was asked to check.");
    }

    [Fact]
    public async Task Says_signature_invalid_when_the_stored_signature_does_not_check_out()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var reportId = Guid.Parse(subject.ReportId);
        var tampered = Tampered(owned.Read(db => db.MedicalReports
            .Single(report => report.PublicId == reportId).Signature));

        owned.Read(db => db.MedicalReports
            .Where(report => report.PublicId == reportId)
            .ExecuteUpdate(set => set.SetProperty(report => report.Signature, tampered)));

        Assert.Equal(VerificationOutcomes.SignatureInvalid, await subject.OutcomeAsync());
    }

    [Fact]
    public async Task Says_unknown_signer_when_the_key_that_signed_it_can_no_longer_be_found()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        owned.Read(db =>
        {
            db.Database.OpenConnection();

            try
            {
                db.Database.ExecuteSqlRaw("PRAGMA foreign_keys = OFF");

                return db.SigningKeys.ExecuteDelete();
            }
            finally
            {
                db.Database.CloseConnection();
            }
        });

        var answer = await subject.VerifyAsync();

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(VerificationOutcomes.UnknownSigner, answer.Text("outcome"));

        Assert.Equal("Dr. Helena Novak", answer.Field("doctor")?.GetProperty("name").GetString());
    }

    [Fact]
    public async Task Tells_this_doctors_signature_apart_from_another_genuine_one()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var key = owned.Read(db => db.SigningKeys.Single());

        Assert.Equal(key.PublicKeyPoint, owned.Hsm.FindKey(key.KeyLabel));
        Assert.Equal(VerificationOutcomes.Valid, await subject.OutcomeAsync());

        var digest = SHA256.HashData(await File.ReadAllBytesAsync(
            subject.DocumentPath, TestContext.Current.CancellationToken));

        owned.Hsm.CreateKey("another-doctors-key");

        var impostor = owned.Hsm.SignDigest("another-doctors-key", digest);
        var reportId = Guid.Parse(subject.ReportId);

        Assert.Equal(2 * Pkcs11Constants.P256CoordinateBytes, impostor.Length);

        owned.Read(db => db.MedicalReports
            .Where(report => report.PublicId == reportId)
            .ExecuteUpdate(set => set.SetProperty(report => report.Signature, impostor)));

        Assert.Equal(VerificationOutcomes.SignatureInvalid, await subject.OutcomeAsync());
    }

    [Fact]
    public async Task Recomputes_from_the_file_on_every_call_rather_than_answering_from_a_cache()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var pdf = await File.ReadAllBytesAsync(
            subject.DocumentPath, TestContext.Current.CancellationToken);

        Assert.Equal(VerificationOutcomes.Valid, await subject.OutcomeAsync());

        File.Delete(subject.DocumentPath);

        Assert.Equal(VerificationOutcomes.FileMissing, await subject.OutcomeAsync());

        await File.WriteAllBytesAsync(
            subject.DocumentPath, pdf, TestContext.Current.CancellationToken);

        Assert.Equal(VerificationOutcomes.Valid, await subject.OutcomeAsync());
    }

    [Fact]
    public async Task Leaves_the_document_exactly_as_it_found_it()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var before = await File.ReadAllBytesAsync(
            subject.DocumentPath, TestContext.Current.CancellationToken);

        await subject.OutcomeAsync();
        await subject.OutcomeAsync();

        Assert.Equal(before, await File.ReadAllBytesAsync(
            subject.DocumentPath, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Tells_a_third_party_the_report_does_not_exist_rather_than_that_it_is_not_theirs()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        foreach (var stranger in new[] { subject.OtherDoctorToken, subject.OtherPatientToken })
        {
            var answer = await subject.VerifyAsync(stranger);

            Assert.Equal(HttpStatusCode.NotFound, answer.Status);
            Assert.Equal(Problem.ContentType, answer.ContentType);
            Assert.DoesNotContain("Kovač", answer.Raw);
            Assert.DoesNotContain("Novak", answer.Raw);
        }

        var neverIssued = await owned.CreateClient()
            .AskAsync(Api.Verification(Guid.NewGuid().ToString()), subject.DoctorToken);

        Assert.Equal(HttpStatusCode.NotFound, neverIssued.OrSkip().Status);
    }

    [Fact]
    public async Task Refuses_to_verify_anything_without_a_session()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var answer = await owned.CreateClient().AskAsync(Api.Verification(subject.ReportId));

        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
        Assert.Equal(Problem.ContentType, answer.ContentType);
    }

    private static byte[] Tampered(byte[] signature) =>
        [.. signature[..^1], (byte)(signature[^1] ^ 0xFF)];
}
