using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using MedSign.Api.Hsm.Contracts;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MedSign.Tests;

public sealed class MedSignHost : WebApplicationFactory<Program>
{
    private readonly SqliteConnection _keepAlive;

    private readonly int? _sessionLifetimeMinutes;

    public MedSignHost(int? sessionLifetimeMinutes = null)
    {
        _sessionLifetimeMinutes = sessionLifetimeMinutes;
        ConnectionString = $"Data Source=file:{Guid.NewGuid():n}?mode=memory&cache=shared";

        _keepAlive = new SqliteConnection(ConnectionString);
        _keepAlive.Open();

        StorageRoot = Path.Combine(Path.GetTempPath(), $"medsign-{Guid.NewGuid():n}");
    }

    public string ConnectionString { get; }

    public string StorageRoot { get; }

    public string DocumentPath(string reportId) =>
        Path.Combine(StorageRoot, "reports", $"{reportId}.pdf");

    public Dictionary<string, string?> Settings { get; } = [];

    public const string Origin = Lab.Origin;

    public const string RpId = Lab.RpId;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting(EnvJwtSigningProvider.KeyVariable, Build.SigningKey);

        builder.UseSetting("ConnectionStrings:MedSign", ConnectionString);
        builder.UseSetting("Storage:Root", StorageRoot);
        builder.UseSetting("Passkey:RpId", RpId);
        builder.UseSetting("Passkey:RpName", "MedSign Cloud");
        builder.UseSetting("Passkey:Origins:0", Origin);
        builder.UseSetting("Passkey:TimeoutMs", "120000");
        builder.UseSetting("Passkey:ChallengeLifetime", "00:05:00");

        if (_sessionLifetimeMinutes is { } minutes)
        {
            builder.UseSetting("Jwt:LifetimeMinutes", minutes.ToString(CultureInfo.InvariantCulture));
        }

        foreach (var (key, value) in Settings)
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IDocumentSigner>();
            services.AddSingleton<IDocumentSigner>(Hsm);
        });
    }

    public FakeDocumentSigner Hsm { get; } = new();

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

    public string TokenFor(User user)
    {
        using var scope = Services.CreateScope();
        var services = scope.ServiceProvider;

        var key = services.GetRequiredService<IJwtSigningKeyStore>().Current()
            ?? throw new InvalidOperationException(
                "The host provisioned no JWT Signing Key, so it cannot issue a session.");

        return services.GetRequiredService<JwtIssuer>().IssueJwt(user, key);
    }

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

        Hsm.Dispose();
        _keepAlive.Dispose();
        SqliteConnection.ClearAllPools();

        if (Directory.Exists(StorageRoot))
        {
            Directory.Delete(StorageRoot, recursive: true);
        }
    }
}

public sealed record Answer(HttpStatusCode Status, JsonElement Body, string Raw)
{
    public bool Ok => Status == HttpStatusCode.OK;

    public string? ContentType { get; init; }

    public IReadOnlyList<JsonElement> Items => Body.ValueKind == JsonValueKind.Array
        ? [.. Body.EnumerateArray()]
        : [];

    public JsonElement? Field(string name) =>
        Body.ValueKind == JsonValueKind.Object && Body.TryGetProperty(name, out var value)
            ? value
            : null;

    public string? Text(string name) => Field(name)?.GetString();

    public byte[] Bytes(string name) => Base64Url.Decode(
        Text(name) ?? throw new InvalidOperationException(
            $"The answer has no '{name}':\n{Raw}"));

    public byte[] Bytes2(string parent, string name) => Base64Url.Decode(
        Field(parent)?.GetProperty(name).GetString() ?? throw new InvalidOperationException(
            $"The answer has no '{parent}.{name}':\n{Raw}"));

    public IReadOnlyList<string> Shape() => Body.ValueKind == JsonValueKind.Object
        ? [.. Body.EnumerateObject().Select(property => property.Name)]
        : [];
}

public static class Api
{
    public const string RegistrationChallenge = "/api/auth/registration-challenge";
    public const string Registration = "/api/auth/registration";
    public const string SignInChallenge = "/api/auth/sign-in-challenge";
    public const string SignIn = "/api/auth/sign-in";

    public const string Patients = "/api/patients";

    public const string SigningStatus = "/api/signing/status";
    public const string SigningEnable = "/api/signing/enable";

    public const string Reports = "/api/reports";

    public static string Report(string id) => $"{Reports}/{id}";

    public static string Document(string id) => $"{Reports}/{id}/document";

    public static string Verification(string id) => $"{Reports}/{id}/verification";

    public static async Task<Answer> PostAsync(
        this HttpClient client, string route, object? body = null, string? token = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route);

        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        Present(request, token);

        return await ReadAsync(await client.SendAsync(request));
    }

    public static async Task<Answer> AskAsync(this HttpClient client, string route, string? token = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, route);

        Present(request, token);

        return await ReadAsync(await client.SendAsync(request));
    }

    public static Task<HttpResponseMessage> FetchAsync(
        this HttpClient client, string route, string? token = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, route);

        Present(request, token);

        return client.SendAsync(request);
    }

    private static void Present(HttpRequestMessage request, string? token)
    {
        if (token is not null)
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
        }
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

public static class EndpointExercise
{
    private const string Pending = "Not implemented yet -- this is the exercise.";

    public static Answer OrSkip(this Answer answer)
    {
        if (answer.Status == HttpStatusCode.NotImplemented)
        {
            Assert.Skip(Pending);
        }

        return answer;
    }

    public static bool Refused(this Answer answer) => !answer.OrSkip().Ok;
}
