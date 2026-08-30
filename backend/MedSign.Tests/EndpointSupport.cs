using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using MedSign.Api.Auth;
using MedSign.Api.Passkeys;
using MedSign.Api.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace MedSign.Tests;

/// <summary>
/// The whole application, in memory, wired the way Program.cs wires it.
///
/// The endpoint exercises are about what MedSign puts on the wire -- which
/// refusals look alike, what a duplicate credential does, whether the new
/// signature counter survives the request -- and none of that is visible from
/// inside a handler. So these tests go over HTTP, through the real routing,
/// serialisation and middleware, against a database that lives and dies with
/// the test.
/// </summary>
public sealed class MedSignHost : WebApplicationFactory<Program>
{
    private readonly TempContentRoot _root = new();

    /// <summary>
    /// Held open for the lifetime of the host: an in-memory SQLite database exists
    /// only while something is connected to it.
    /// </summary>
    private readonly SqliteConnection _keepAlive;

    public MedSignHost()
    {
        ConnectionString = $"Data Source=file:{Guid.NewGuid():n}?mode=memory&cache=shared";

        _keepAlive = new SqliteConnection(ConnectionString);
        _keepAlive.Open();
    }

    public string ConnectionString { get; }

    /// <summary>The one origin this relying party accepts, as the tests configure it.</summary>
    public const string Origin = Lab.Origin;

    public const string RpId = Lab.RpId;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // EnvFileSigningProvider writes the JWT signing key into the content root.
        // A disposable directory keeps that out of the repository.
        builder.UseContentRoot(_root.ContentRootPath);

        builder.UseSetting("ConnectionStrings:MedSign", ConnectionString);
        builder.UseSetting("Passkey:RpId", RpId);
        builder.UseSetting("Passkey:RpName", "MedSign Cloud");
        builder.UseSetting("Passkey:Origins:0", Origin);
        builder.UseSetting("Passkey:TimeoutMs", "120000");
        builder.UseSetting("Passkey:ChallengeLifetime", "00:05:00");
    }

    /// <summary>
    /// An account that already holds this authenticator's passkey, written straight
    /// to the database -- the state a finished registration leaves behind, without
    /// depending on the registration exercise being done.
    /// </summary>
    public User Enrol(VirtualAuthenticator authenticator, string username = "h.novak", long signCount = 0)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MedSignDb>();

        var user = new User
        {
            Username = username,
            Handle = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32),
            DisplayName = "Dr. Helena Novak",
            Role = Roles.Doctor,
            Credentials =
            [
                Build.Credential(authenticator.CredentialId, authenticator.PublicKeyPoint, signCount),
            ],
        };

        db.Users.Add(user);
        db.SaveChanges();

        return user;
    }

    /// <summary>Reads the database the application just wrote to.</summary>
    public T Read<T>(Func<MedSignDb, T> read)
    {
        using var scope = Services.CreateScope();

        return read(scope.ServiceProvider.GetRequiredService<MedSignDb>());
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        _keepAlive.Dispose();
        SqliteConnection.ClearAllPools();
        _root.Dispose();
    }
}

/// <summary>
/// One request and its answer, kept together so a test can assert on the status
/// and the body without threading both through every helper.
/// </summary>
public sealed record Answer(HttpStatusCode Status, JsonElement Body, string Raw)
{
    public bool Ok => Status == HttpStatusCode.OK;

    /// <summary>The named property, or null when the answer does not carry one.</summary>
    public JsonElement? Field(string name) =>
        Body.ValueKind == JsonValueKind.Object && Body.TryGetProperty(name, out var value)
            ? value
            : null;

    public string? Text(string name) => Field(name)?.GetString();

    /// <summary>Decodes a base64url field the browser would have handed to the authenticator.</summary>
    public byte[] Bytes(string name) => Base64Url.Decode(
        Text(name) ?? throw new InvalidOperationException(
            $"The answer has no '{name}':\n{Raw}"));

    /// <summary>A base64url field one level down, e.g. user.id on a creation ceremony.</summary>
    public byte[] Bytes2(string parent, string name) => Base64Url.Decode(
        Field(parent)?.GetProperty(name).GetString() ?? throw new InvalidOperationException(
            $"The answer has no '{parent}.{name}':\n{Raw}"));

    /// <summary>The property names on the answer, in order -- what a caller can see.</summary>
    public IReadOnlyList<string> Shape() => Body.ValueKind == JsonValueKind.Object
        ? [.. Body.EnumerateObject().Select(property => property.Name)]
        : [];
}

/// <summary>The four passkey routes, as the browser calls them.</summary>
public static class Api
{
    public const string RegistrationChallenge = "/api/auth/registration-challenge";
    public const string Registration = "/api/auth/registration";
    public const string SignInChallenge = "/api/auth/sign-in-challenge";
    public const string SignIn = "/api/auth/sign-in";

    public static async Task<Answer> PostAsync(this HttpClient client, string route, object body)
    {
        var response = await client.PostAsJsonAsync(route, body);
        var raw = await response.Content.ReadAsStringAsync();

        var parsed = raw.Length == 0
            ? default
            : JsonDocument.Parse(raw).RootElement.Clone();

        return new Answer(response.StatusCode, parsed, raw);
    }

    public static object Account(string username, string fullName = "Dr. Helena Novak",
        string role = Roles.Doctor) =>
        new { username, fullName, role };

    public static object Registration_(string username, PasskeyRegistration credential,
        string fullName = "Dr. Helena Novak", string role = Roles.Doctor) =>
        new { username, fullName, role, credential };

    public static object SignIn_(string username, PasskeyAssertion? assertion) =>
        new { username, assertion };
}

/// <summary>
/// The endpoint half of <see cref="Exercise"/>.
///
/// ProblemMiddleware turns the NotImplementedException an unstarted exercise
/// throws into 501, so a test can tell "nobody has written this yet" apart from
/// "this is wrong" without reaching inside the application.
/// </summary>
public static class EndpointExercise
{
    private const string Pending = "Not implemented yet -- this is the exercise.";

    /// <summary>The answer, unless the exercise behind it has not been started.</summary>
    public static Answer OrSkip(this Answer answer)
    {
        if (answer.Status == HttpStatusCode.NotImplemented)
        {
            Assert.Skip(Pending);
        }

        return answer;
    }

    /// <summary>
    /// True when MedSign refused. Any answer that is not 200 is a refusal here:
    /// which status a refusal carries is asserted where it matters, and this is
    /// for the cases where the only thing that must hold is "not a session".
    /// </summary>
    public static bool Refused(this Answer answer) => !answer.OrSkip().Ok;
}
