using System.Net;
using System.Text.Json;
using MedSign.Api.Hsm;
using MedSign.Api.Shared;

namespace MedSign.Tests;

/// <summary>
/// Reading reports back: the list, the single report, and the PDF.
///
/// One list endpoint serves both roles and means a different thing to each --
/// issued-by for a doctor, issued-to for a patient -- because the caller's
/// session is what decides, not a parameter the client supplies. There is no
/// query a doctor can send that shows them a colleague's caseload.
///
/// The refusal is the other half. Someone who is party to neither side of a
/// report gets 404 rather than 403, and the same 404 a report that was never
/// issued would produce: a 403 would confirm the report exists, which is
/// exactly the fact worth hiding.
/// </summary>
public class ReportAccessTests
{
    /// <summary>
    /// Two doctors, two patients, and the tokens for all four, all issued
    /// through the endpoints so these tests read back a state the application
    /// itself produced.
    /// </summary>
    private static async Task<Ward> WardAsync()
    {
        var host = new MedSignHost();

        var novak = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");
        var babic = host.Account("i.babic", Roles.Doctor, "Dr. Ivan Babić");
        var kovac = host.Account("m.kovac", Roles.Patient, "Marko Kovač");
        var horvat = host.Account("a.horvat", Roles.Patient, "Ana Horvat");

        var ward = new Ward(host, kovac, horvat,
            host.TokenFor(novak), host.TokenFor(babic),
            host.TokenFor(kovac), host.TokenFor(horvat));

        var client = host.CreateClient();

        await client.PostAsync(Api.SigningEnable, token: ward.NovakToken);
        await client.PostAsync(Api.SigningEnable, token: ward.BabicToken);

        return ward;
    }

    private sealed record Ward(
        MedSignHost Host,
        User Kovac,
        User Horvat,
        string NovakToken,
        string BabicToken,
        string KovacToken,
        string HorvatToken)
    {
        public const string Findings = "Blood pressure 128/82. No further action.";

        /// <summary>Issues a report and hands back the id the API gave it.</summary>
        public async Task<string> IssueAsync(string doctorToken, User patient, string? body = null)
        {
            var answer = await Host.CreateClient().PostAsync(Api.Reports, new
            {
                patientId = patient.Id,
                type = ReportTypes.Findings,
                body = body ?? Findings,
            }, doctorToken);

            Assert.Equal(HttpStatusCode.OK, answer.Status);

            return answer.Text("id")!;
        }

        public Task<Answer> ListAsync(string token) =>
            Host.CreateClient().AskAsync(Api.Reports, token);

        public Task<Answer> ReadAsync(string id, string token) =>
            Host.CreateClient().AskAsync(Api.Report(id), token);
    }

    [Fact]
    public async Task Shows_a_doctor_the_reports_they_issued_and_not_a_colleagues()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var mine = await ward.IssueAsync(ward.NovakToken, ward.Kovac);

        // The same patient, a different doctor: what separates the two lists is
        // who wrote the report, not who it is about.
        var colleagues = await ward.IssueAsync(ward.BabicToken, ward.Kovac);

        var answer = await ward.ListAsync(ward.NovakToken);

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(mine, Assert.Single(answer.Items).GetProperty("id").GetString());
        Assert.DoesNotContain(colleagues, answer.Raw);
        Assert.DoesNotContain("Babić", answer.Raw);
    }

    [Fact]
    public async Task Shows_a_patient_the_reports_issued_to_them_and_not_another_patients()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var mine = await ward.IssueAsync(ward.NovakToken, ward.Kovac);
        var anothers = await ward.IssueAsync(ward.NovakToken, ward.Horvat);

        var answer = await ward.ListAsync(ward.KovacToken);

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(mine, Assert.Single(answer.Items).GetProperty("id").GetString());
        Assert.DoesNotContain(anothers, answer.Raw);
        Assert.DoesNotContain("Horvat", answer.Raw);
    }

    [Fact]
    public async Task Answers_with_a_bare_array_newest_first_and_empty_when_there_is_nothing()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var empty = await ward.ListAsync(ward.NovakToken);

        // A bare array rather than an envelope, and an empty one rather than a
        // refusal: a doctor who has issued nothing has an empty caseload.
        Assert.Equal(JsonValueKind.Array, empty.Body.ValueKind);
        Assert.Empty(empty.Items);

        var first = await ward.IssueAsync(ward.NovakToken, ward.Kovac);
        var second = await ward.IssueAsync(ward.NovakToken, ward.Horvat);
        var third = await ward.IssueAsync(ward.NovakToken, ward.Kovac);

        var answer = await ward.ListAsync(ward.NovakToken);

        Assert.Equal(JsonValueKind.Array, answer.Body.ValueKind);
        Assert.Equal(
            [third, second, first],
            answer.Items.Select(report => report.GetProperty("id").GetString()));
    }

    [Fact]
    public async Task Carries_an_excerpt_rather_than_the_whole_body()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var body = string.Join(' ', Enumerable.Repeat("Patient reports intermittent headaches.", 40));

        await ward.IssueAsync(ward.NovakToken, ward.Kovac, body);

        var report = Assert.Single((await ward.ListAsync(ward.NovakToken)).Items);
        var excerpt = report.GetProperty("excerpt").GetString()!;

        // A list of forty reports must not be forty whole documents on the wire.
        Assert.False(report.TryGetProperty("body", out _), "The summary carries the full body.");
        Assert.True(excerpt.Length < body.Length, "The excerpt is the whole body.");
        Assert.StartsWith("Patient reports intermittent headaches.", excerpt);
    }

    [Fact]
    public async Task Leaves_a_body_that_already_fits_alone()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        await ward.IssueAsync(ward.NovakToken, ward.Kovac, Ward.Findings);

        var report = Assert.Single((await ward.ListAsync(ward.NovakToken)).Items);

        // Nothing is elided from a report short enough to read in the list.
        Assert.Equal(Ward.Findings, report.GetProperty("excerpt").GetString());
    }

    [Fact]
    public async Task Names_the_counterparty_on_both_sides_of_the_same_report()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        await ward.IssueAsync(ward.NovakToken, ward.Kovac);

        var doctors = Assert.Single((await ward.ListAsync(ward.NovakToken)).Items);
        var patients = Assert.Single((await ward.ListAsync(ward.KovacToken)).Items);

        // A doctor's list is a list of patients; a patient's list is a list of
        // doctors. One shape answers both, so both names are on every entry.
        Assert.Equal("Marko Kovač", doctors.GetProperty("patient").GetProperty("name").GetString());
        Assert.Equal("Dr. Helena Novak", patients.GetProperty("doctor").GetProperty("name").GetString());

        Assert.Equal(ReportTypes.Findings, doctors.GetProperty("type").GetString());
        Assert.EndsWith(".pdf", doctors.GetProperty("document").GetProperty("fileName").GetString());
        Assert.Equal("ES256", doctors.GetProperty("signature").GetProperty("algorithm").GetString());
    }

    [Fact]
    public async Task Reads_one_report_in_full_to_either_party()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var id = await ward.IssueAsync(ward.NovakToken, ward.Kovac);

        foreach (var token in new[] { ward.NovakToken, ward.KovacToken })
        {
            var answer = await ward.ReadAsync(id, token);

            Assert.Equal(HttpStatusCode.OK, answer.Status);
            Assert.Equal(id, answer.Text("id"));

            // The excerpt is what a list is for; opening a report is how the
            // rest of it is read.
            Assert.Equal(Ward.Findings, answer.Text("body"));
            Assert.Equal("Marko Kovač", answer.Field("patient")?.GetProperty("name").GetString());
            Assert.Equal("Dr. Helena Novak", answer.Field("doctor")?.GetProperty("name").GetString());
            Assert.NotNull(answer.Field("signature"));
        }
    }

    [Fact]
    public async Task Tells_a_third_party_the_report_does_not_exist_rather_than_that_it_is_not_theirs()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var id = await ward.IssueAsync(ward.NovakToken, ward.Kovac);

        foreach (var route in new[] { Api.Report(id), Api.Document(id) })
        {
            foreach (var stranger in new[] { ward.BabicToken, ward.HorvatToken })
            {
                var answer = await owned.CreateClient().AskAsync(route, stranger);

                // Not 403. A refusal that tells "not yours" apart from "no such
                // thing" tells a stranger that this patient has records.
                Assert.Equal(HttpStatusCode.NotFound, answer.Status);
                Assert.Equal(Problem.ContentType, answer.ContentType);
                Assert.DoesNotContain("Kovač", answer.Raw);
                Assert.DoesNotContain("Novak", answer.Raw);
            }
        }

        var neverIssued = Guid.NewGuid().ToString();

        var missing = await ward.ReadAsync(neverIssued, ward.NovakToken);
        var notTheirs = await ward.ReadAsync(id, ward.BabicToken);

        // Indistinguishable, deliberately: the same status and the same
        // document, with only the id the caller already knows differing.
        Assert.Equal(missing.Status, notTheirs.Status);
        Assert.Equal(
            missing.Raw.Replace(neverIssued, "{id}", StringComparison.Ordinal),
            notTheirs.Raw.Replace(id, "{id}", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Hands_either_party_the_pdf_that_was_signed_under_a_name_they_will_recognise()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var id = await ward.IssueAsync(ward.NovakToken, ward.Kovac);

        var stored = await File.ReadAllBytesAsync(
            owned.DocumentPath(id), TestContext.Current.CancellationToken);

        var fileName = (await ward.ReadAsync(id, ward.NovakToken))
            .Field("document")!.Value.GetProperty("fileName").GetString();

        foreach (var token in new[] { ward.NovakToken, ward.KovacToken })
        {
            using var response = await owned.CreateClient().FetchAsync(Api.Document(id), token);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("application/pdf", response.Content.Headers.ContentType?.MediaType);

            // The bytes that were hashed and signed, not a fresh rendering: a
            // regenerated PDF would not match its own signature.
            Assert.Equal(stored, await response.Content.ReadAsByteArrayAsync(
                TestContext.Current.CancellationToken));

            // The recorded display name, so a downloads folder stays navigable.
            var disposition = response.Content.Headers.ContentDisposition;

            Assert.Equal(fileName, disposition?.FileNameStar ?? disposition?.FileName?.Trim('"'));
        }
    }

    [Fact]
    public async Task Says_so_when_the_document_is_gone_rather_than_rendering_a_new_one()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var id = await ward.IssueAsync(ward.NovakToken, ward.Kovac);

        File.Delete(owned.DocumentPath(id));

        var answer = await owned.CreateClient().AskAsync(Api.Document(id), ward.NovakToken);

        // Gone, not a conflict to retry past: a regenerated PDF would be
        // byte-different, so the signature stored beside it would no longer
        // verify, and a download that quietly re-rendered would hand a patient
        // a document their own records call a forgery.
        Assert.Equal(HttpStatusCode.Gone, answer.Status);
        Assert.Equal(Problem.ContentType, answer.ContentType);

        // The report itself is still readable -- it is the file that is gone,
        // not the record of what was issued.
        Assert.Equal(HttpStatusCode.OK, (await ward.ReadAsync(id, ward.NovakToken)).Status);
    }

    [Fact]
    public async Task Refuses_to_hand_out_a_report_or_a_document_without_a_session()
    {
        var ward = await WardAsync();
        using var owned = ward.Host;

        var id = await ward.IssueAsync(ward.NovakToken, ward.Kovac);
        var client = owned.CreateClient();

        // A guessed URL is not a way in: the file sits behind the same session
        // everything else does.
        foreach (var route in new[] { Api.Reports, Api.Report(id), Api.Document(id) })
        {
            var answer = await client.AskAsync(route);

            Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
            Assert.Equal(Problem.ContentType, answer.ContentType);
        }
    }
}
