using System.Net;
using System.Text.Json;
using MedSign.Api.Shared;

namespace MedSign.Tests;

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

        Assert.Equal("Marko Kovač", patient.GetProperty("fullName").GetString());
        Assert.True(patient.GetProperty("id").GetInt32() > 0);
    }

    [Fact]
    public async Task Leaves_the_doctors_out_of_it()
    {
        using var host = Clinic(out var token);
        host.Account("i.babic", Roles.Doctor, "Dr. Ivan Babić");

        var answer = await host.CreateClient().AskAsync(Api.Patients, token);

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

        var segments = host.TokenFor(patient).Split('.');
        var claims = JsonDocument.Parse(Base64Url.Decode(segments[1])).RootElement
            .EnumerateObject()
            .ToDictionary(claim => claim.Name, claim => (object)claim.Value.Clone());

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

        var answer = await owned.CreateClient()
            .AskAsync(Api.Patients, $"{segments[0]}.{segments[1]}.{Base64Url.Encode(signature)}");

        Assert.Equal(HttpStatusCode.Unauthorized, answer.Status);
    }

    [Fact]
    public async Task Refuses_a_session_that_has_run_out()
    {
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

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
