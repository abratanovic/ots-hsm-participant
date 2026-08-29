using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
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
    /// <summary>
    /// Held open for the lifetime of the host: an in-memory SQLite database exists
    /// only while something is connected to it.
    /// </summary>
    private readonly SqliteConnection _keepAlive;

    private readonly int? _sessionLifetimeMinutes;

    /// <param name="sessionLifetimeMinutes">
    /// How long the tokens this host issues stay good for. A negative lifetime
    /// hands out a token that was already expired when it was signed, which is
    /// how the expiry tests get one without a clock the running app shares.
    /// </param>
    public MedSignHost(int? sessionLifetimeMinutes = null)
    {
        _sessionLifetimeMinutes = sessionLifetimeMinutes;
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
        // The signing key reaches the running app as an environment variable. Handing
        // it to the host as a setting keeps it out of this test process's environment,
        // which every other test would share.
        builder.UseSetting(EnvJwtSigningProvider.KeyVariable, Build.SigningKey);

        builder.UseSetting("ConnectionStrings:MedSign", ConnectionString);
        builder.UseSetting("Passkey:RpId", RpId);
        builder.UseSetting("Passkey:RpName", "MedSign Cloud");
        builder.UseSetting("Passkey:Origins:0", Origin);
        builder.UseSetting("Passkey:TimeoutMs", "120000");
        builder.UseSetting("Passkey:ChallengeLifetime", "00:05:00");

        if (_sessionLifetimeMinutes is { } minutes)
        {
            builder.UseSetting("Jwt:LifetimeMinutes", minutes.ToString(CultureInfo.InvariantCulture));
        }
    }

    /// <summary>
    /// An account with no passkey on it -- everything the session tests need,
    /// without a ceremony. <see cref="Enrol"/> is for the tests that sign in.
    /// </summary>
    public User Account(string username, string role, string fullName)
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<MedSignDb>();

        var user = new User
        {
            Username = username,
            Handle = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32),
            DisplayName = fullName,
            Role = role,
        };

        db.Users.Add(user);
        db.SaveChanges();

        return user;
    }

    /// <summary>
    /// The session token a finished sign-in would hand this account, minted by
    /// the application's own issuer with the application's own key. Going
    /// through the sign-in endpoint instead would make every authorisation test
    /// depend on the passkey exercise being finished.
    /// </summary>
    public string TokenFor(User user)
    {
        using var scope = Services.CreateScope();
        var services = scope.ServiceProvider;

        var key = services.GetRequiredService<IJwtSigningKeyStore>().Current()
            ?? throw new InvalidOperationException(
                "The host provisioned no JWT Signing Key, so it cannot issue a session.");

        return services.GetRequiredService<JwtIssuer>().IssueJwt(user, key);
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
    }
}

/// <summary>
/// One request and its answer, kept together so a test can assert on the status
/// and the body without threading both through every helper.
/// </summary>
public sealed record Answer(HttpStatusCode Status, JsonElement Body, string Raw)
{
    public bool Ok => Status == HttpStatusCode.OK;

    /// <summary>The media type MedSign labelled the body with, if any.</summary>
    public string? ContentType { get; init; }

    /// <summary>The elements of a bare JSON array answer, in the order they arrived.</summary>
    public IReadOnlyList<JsonElement> Items => Body.ValueKind == JsonValueKind.Array
        ? [.. Body.EnumerateArray()]
        : [];

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

    /// <summary>The first endpoint behind a session.</summary>
    public const string Patients = "/api/patients";

    public static async Task<Answer> PostAsync(this HttpClient client, string route, object body) =>
        await ReadAsync(await client.PostAsJsonAsync(route, body));

    /// <summary>
    /// A GET, optionally carrying a session. Not named GetAsync: an extension
    /// never wins against HttpClient's own method, so the token would be
    /// silently dropped.
    ///
    /// The token goes on unvalidated, because half the point is to send tokens
    /// that are not well formed.
    /// </summary>
    public static async Task<Answer> AskAsync(this HttpClient client, string route, string? token = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, route);

        if (token is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        }

        return await ReadAsync(await client.SendAsync(request));
    }

    private static async Task<Answer> ReadAsync(HttpResponseMessage response)
    {
        var raw = await response.Content.ReadAsStringAsync();

        var parsed = raw.Length == 0
            ? default
            : JsonDocument.Parse(raw).RootElement.Clone();

        return new Answer(response.StatusCode, parsed, raw)
        {
            ContentType = response.Content.Headers.ContentType?.MediaType,
        };
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
