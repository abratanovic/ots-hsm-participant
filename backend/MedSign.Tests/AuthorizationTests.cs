using System.Net;
using System.Text.Json;
using MedSign.Api.Shared;

namespace MedSign.Tests;

/// <summary>
/// GET /api/patients -- the first endpoint that reads a session back rather
/// than handing one out.
///
/// A doctor needs somebody to address a report to, and this is where the
/// frontend's recipient picker comes from. What it must never be is a
/// directory of everyone with an account.
/// </summary>
public class PatientListTests
{
    private static MedSignHost Clinic(out string doctorToken)
    {
        var host = new MedSignHost();

        var doctor = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");
        host.Account("m.kovac", Roles.Patient, "Marko Kovač");
        host.Account("a.horvat", Roles.Patient, "Ana Horvat");

        doctorToken = host.TokenFor(doctor);

        return host;
    }

    [Fact]
    public async Task Names_every_patient_a_report_could_be_addressed_to()
    {
        using var host = Clinic(out var token);

        var answer = await host.CreateClient().AskAsync(Api.Patients, token);

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(2, answer.Items.Count);

        var patient = answer.Items.Single(p => p.GetProperty("username").GetString() == "m.kovac");

        // The picker shows the name and sends the id, so both have to be here.
        Assert.Equal("Marko Kovač", patient.GetProperty("fullName").GetString());
        Assert.True(patient.GetProperty("id").GetInt32() > 0);
    }

    [Fact]
    public async Task Leaves_the_doctors_out_of_it()
    {
        using var host = Clinic(out var token);
        host.Account("i.babic", Roles.Doctor, "Dr. Ivan Babić");

        var answer = await host.CreateClient().AskAsync(Api.Patients, token);

        // A colleague in the picker is a findings report filed against another
        // doctor's account, one mis-click away.
        Assert.DoesNotContain("i.babic", answer.Raw);
        Assert.DoesNotContain("h.novak", answer.Raw);
        Assert.All(answer.Items, patient =>
            Assert.Contains(patient.GetProperty("username").GetString(), new[] { "m.kovac", "a.horvat" }));
    }

    [Fact]
    public async Task Tells_a_patient_this_is_not_theirs_to_ask()
    {
        using var host = Clinic(out _);
        var patient = host.Account("z.maric", Roles.Patient, "Zoran Marić");

        var answer = await host.CreateClient().AskAsync(Api.Patients, host.TokenFor(patient));

        // Not 401: the session is perfectly good, the role is wrong. Answering
        // this one would hand every patient the clinic's whole roster.
        Assert.Equal(HttpStatusCode.Forbidden, answer.Status);
        Assert.DoesNotContain("m.kovac", answer.Raw);
    }

    [Fact]
    public async Task Answers_an_empty_clinic_with_an_empty_list()
    {
        using var host = new MedSignHost();
        var doctor = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");

        var answer = await host.CreateClient().AskAsync(Api.Patients, host.TokenFor(doctor));

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(JsonValueKind.Array, answer.Body.ValueKind);
        Assert.Empty(answer.Items);
    }
}

/// <summary>
/// The session itself, exercised through the one endpoint that requires it.
///
/// MedSign signs its own tokens with its own key, so a token that verifies is
/// trusted for what it says. That is only safe if every way of presenting one
/// MedSign did not issue -- or issued and has since outlived -- is turned down,
/// which is what these say.
/// </summary>
public class SessionTests
{
    private static (MedSignHost Host, string Token) Signed(int? lifetimeMinutes = null)
    {
        var host = new MedSignHost(lifetimeMinutes);
        var doctor = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");

        return (host, host.TokenFor(doctor));
    }

    [Fact]
    public async Task Refuses_a_request_carrying_no_token_at_all()
    {
        using var host = new MedSignHost();
        host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");

        var answer = await host.CreateClient().AskAsync(Api.Patients);

        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
    }

    [Fact]
    public async Task Refuses_a_token_that_is_not_a_token()
    {
        var (host, _) = Signed();
        using var owned = host;

        var answer = await owned.CreateClient().AskAsync(Api.Patients, "not-a-jws-at-all");

        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
    }

    [Fact]
    public async Task Refuses_a_token_whose_claims_were_rewritten()
    {
        using var host = new MedSignHost();
        var patient = host.Account("m.kovac", Roles.Patient, "Marko Kovač");

        // The promotion a patient would give themselves if the role in a token
        // were taken at face value.
        var segments = host.TokenFor(patient).Split('.');
        var claims = JsonDocument.Parse(Base64Url.Decode(segments[1])).RootElement
            .EnumerateObject()
            .ToDictionary(claim => claim.Name, claim => (object)claim.Value.Clone());

        // Anyone can read a JWT and anyone can edit one. The signature is the
        // only reason the role inside it means anything.
        claims["role"] = Roles.Doctor;

        var forged = $"{segments[0]}."
            + $"{Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(claims))}."
            + segments[2];

        var answer = await host.CreateClient().AskAsync(Api.Patients, forged);

        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
    }

    [Fact]
    public async Task Refuses_a_token_signed_by_something_else()
    {
        var (host, token) = Signed();
        using var owned = host;

        var segments = token.Split('.');
        var signature = Base64Url.Decode(segments[2]);
        signature[0] ^= 0xFF;

        // Still 64 bytes of well-formed base64url, so nothing short of the curve
        // arithmetic can tell this apart from the real thing.
        var answer = await owned.CreateClient()
            .AskAsync(Api.Patients, $"{segments[0]}.{segments[1]}.{Base64Url.Encode(signature)}");

        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
    }

    [Fact]
    public async Task Refuses_a_session_that_has_run_out()
    {
        // Issued with a lifetime that had already elapsed, so this token is
        // genuinely signed and genuinely expired.
        var (host, token) = Signed(lifetimeMinutes: -1);
        using var owned = host;

        var answer = await owned.CreateClient().AskAsync(Api.Patients, token);

        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
    }

    [Fact]
    public async Task Explains_a_refusal_the_way_it_explains_everything_else()
    {
        using var host = new MedSignHost();

        var answer = await host.CreateClient().AskAsync(Api.Patients);

        // The frontend has one error mapping. A refusal that arrives as an empty
        // body or an unhandled exception is one it cannot render.
        Assert.Equal(Problem.ContentType, answer.ContentType);
        Assert.Equal(401, answer.Field("status")?.GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(answer.Text("title")));
        Assert.False(string.IsNullOrWhiteSpace(answer.Text("detail")));
    }

    [Fact]
    public async Task Leaves_the_ceremonies_that_hand_out_sessions_open()
    {
        using var host = new MedSignHost();
        host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");

        // You cannot present a session to the endpoints you get one from.
        var registration = await host.CreateClient()
            .PostAsync(Api.RegistrationChallenge, Api.Account("i.babic"));

        Assert.Equal(HttpStatusCode.OK, registration.OrSkip().Status);

        var signIn = await host.CreateClient()
            .PostAsync(Api.SignInChallenge, new { username = "h.novak" });

        Assert.Equal(HttpStatusCode.OK, signIn.OrSkip().Status);
    }

    [Fact]
    public async Task Ignores_a_bad_token_on_an_endpoint_that_never_asked_for_one()
    {
        using var host = new MedSignHost();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/.well-known/jwks.json");
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer nonsense");

        var response = await host.CreateClient().SendAsync(request);

        // The public key set is public. A caller waving a broken token at it is
        // not a reason to stop answering.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
