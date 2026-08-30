using System.Net;
using System.Security.Cryptography;
using MedSign.Api.Hsm;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Tests;

/// <summary>
/// GET /api/reports/{id}/verification.
///
/// The payoff of the whole feature, and the one question a signed document
/// exists to answer: did this doctor write this, and has anyone changed it
/// since. MedSign answers it by re-reading the file from disk and re-checking
/// the stored signature against the stored public point every single time --
/// never from a cache, because a cached answer describes a file that may no
/// longer be there.
///
/// It answers specifically rather than with a bare yes or no, and every one of
/// the five outcomes below is reached by manipulating real state: an untouched
/// file, bytes rewritten on disk, the file deleted, the signature altered in
/// the database, the key row removed. A stub agreeing with itself would prove
/// none of it.
/// </summary>
public class ReportVerificationTests
{
    /// <summary>
    /// A doctor with signing enabled, a patient, a stranger on each side, and
    /// one issued report -- all of it produced through the endpoints, so what
    /// these tests check is what the application itself wrote.
    /// </summary>
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

        Assert.Equal(HttpStatusCode.OK, issued.Status);

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

        public Task<Answer> VerifyAsync(string? token = null) =>
            Host.CreateClient().AskAsync(Api.Verification(ReportId), token ?? DoctorToken);

        /// <summary>The outcome MedSign gives right now, having asserted it answered at all.</summary>
        public async Task<string?> OutcomeAsync(string? token = null)
        {
            var answer = await VerifyAsync(token);

            // 200 in every case, including the ones that say "not genuine":
            // that is a successful answer to the question asked.
            Assert.Equal(HttpStatusCode.OK, answer.Status);

            return answer.Text("outcome");
        }
    }

    [Fact]
    public async Task Says_valid_for_an_untouched_file_and_names_the_doctor_the_key_and_the_algorithm()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        var answer = await subject.VerifyAsync();

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(VerificationOutcomes.Valid, answer.Text("outcome"));

        // A positive answer names a person. "Valid" on its own says a signature
        // checked out against something; this says whose key it was.
        Assert.Equal("Dr. Helena Novak", answer.Field("doctor")?.GetProperty("name").GetString());
        Assert.Equal("h.novak", answer.Field("doctor")?.GetProperty("username").GetString());
        Assert.Equal(DoctorKeyLabel.For(subject.Doctor.Id), answer.Text("keyLabel"));
        Assert.Equal(SignatureView.Es256, answer.Text("algorithm"));

        // When the check happened, because the answer is only about that moment.
        Assert.True(answer.Field("checkedAt")?.TryGetDateTimeOffset(out _) ?? false,
            $"The answer carries no checkedAt:\n{answer.Raw}");

        Assert.Equal(subject.ReportId, answer.Text("reportId"));
    }

    [Fact]
    public async Task Answers_the_patient_the_report_is_about_as_readily_as_the_doctor()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        // The patient is who this matters most to: they hold a document and
        // want to know whether their doctor really wrote it.
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

        // One byte, in a real file on a real disk. This is the outcome the
        // stored hash exists to make distinguishable at all.
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

        // An operational problem, said as one. A patient whose file has been
        // lost has not been handed a forged report, and must not be told so.
        Assert.Equal(VerificationOutcomes.FileMissing, await subject.OutcomeAsync());

        // And nothing re-rendered it to have something to check: a regenerated
        // PDF is byte-different, so its signature would not verify -- checking
        // one would destroy the very claim being checked.
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

        // The file is untouched and hashes as recorded; it is the signature
        // itself that no longer verifies against the doctor's key.
        Assert.Equal(VerificationOutcomes.SignatureInvalid, await subject.OutcomeAsync());
    }

    [Fact]
    public async Task Says_unknown_signer_when_the_key_that_signed_it_can_no_longer_be_found()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        owned.Read(db =>
        {
            // The report still names the key it was signed with; the row that
            // held the public half is what has gone.
            //
            // The connection is opened by hand for both statements. PRAGMA
            // foreign_keys is a property of one connection, and EF otherwise
            // opens and closes one per command -- so under the parallelism of a
            // full suite run the DELETE could be handed a connection the PRAGMA
            // had never reached, and fail on the foreign key this is switching
            // off. Holding the connection open makes the two statements
            // provably the same conversation.
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

        // Not "invalid". Nothing about the document has changed -- MedSign
        // simply no longer holds the public half it would need to check it, and
        // "invalid" would accuse a doctor of something they did not do.
        var answer = await subject.VerifyAsync();

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(VerificationOutcomes.UnknownSigner, answer.Text("outcome"));

        // The report is still a report and the doctor is still named; it is
        // only the key that cannot be found.
        Assert.Equal("Dr. Helena Novak", answer.Field("doctor")?.GetProperty("name").GetString());
        Assert.Null(answer.Text("keyLabel"));
    }

    [Fact]
    public async Task Tells_this_doctors_signature_apart_from_another_genuine_one()
    {
        var subject = await CaseAsync();
        using var owned = subject.Host;

        // The public half MedSign is checking against is the public half of a
        // key the device is really holding -- not a value the application made
        // up and then agreed with.
        var key = owned.Read(db => db.SigningKeys.Single());

        Assert.Equal(key.PublicKeyPoint, owned.Hsm.FindKey(key.KeyLabel));
        Assert.Equal(VerificationOutcomes.Valid, await subject.OutcomeAsync());

        var digest = SHA256.HashData(await File.ReadAllBytesAsync(
            subject.DocumentPath, TestContext.Current.CancellationToken));

        // A real P-256 signature, over the right digest, in the right encoding
        // -- made by somebody else's key. Nothing about its shape is wrong, so
        // only genuine curve arithmetic against this doctor's stored point can
        // tell it apart from the real one.
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

        // Valid again, because the answer is about the file as it is now and
        // nothing was remembered from either of the calls before it.
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

        // A GET, because asking whether a document is genuine changes nothing
        // about it -- least of all the bytes whose digest was signed.
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

            // The same 404 the other single-report routes give, and for the
            // same reason: a 403 would confirm this patient has records.
            Assert.Equal(HttpStatusCode.NotFound, answer.Status);
            Assert.Equal(Problem.ContentType, answer.ContentType);
            Assert.DoesNotContain("Kovač", answer.Raw);
            Assert.DoesNotContain("Novak", answer.Raw);
        }

        var neverIssued = await owned.CreateClient()
            .AskAsync(Api.Verification(Guid.NewGuid().ToString()), subject.DoctorToken);

        Assert.Equal(HttpStatusCode.NotFound, neverIssued.Status);
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

    /// <summary>The stored signature with one byte flipped: still 64 bytes, still ES256, no longer this doctor's.</summary>
    private static byte[] Tampered(byte[] signature) =>
        [.. signature[..^1], (byte)(signature[^1] ^ 0xFF)];
}
