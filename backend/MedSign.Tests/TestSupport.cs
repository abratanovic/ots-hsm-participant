using System.Security.Cryptography;
using Fido2NetLib;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace MedSign.Tests;

public sealed class TestClock(DateTimeOffset now) : TimeProvider
{
    private DateTimeOffset _now = now;

    public TestClock() : this(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero))
    {
    }

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

public static class Build
{
    public static IOptions<T> Options<T>(T value) where T : class => Microsoft.Extensions.Options.Options.Create(value);

    public const string SigningKey =
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzjl/8eJg/Fu0EnMEdlpr7DkHAUXs5OpDduuoRBCs"
        + "JJChRANCAASs4HiKlIMdERgbsk9M1p0UOGkHyx3PtmyWWfGUstwo5Ov/+L89eFzDgFcFdbxHGTWaAxYzswo1GQa"
        + "3hMZspFd7";

    public static EnvJwtSigningProvider Signing(TimeProvider clock, string? key = null) =>
        new(Configuration(EnvJwtSigningProvider.KeyVariable, key ?? SigningKey), clock);

    public static IConfiguration Configuration(params string?[] keysAndValues) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(Enumerable
                .Range(0, keysAndValues.Length / 2)
                .Select(i => new KeyValuePair<string, string?>(keysAndValues[i * 2]!, keysAndValues[(i * 2) + 1]))
                .ToList())
            .Build();

    public static MedSignDb Database()
    {
        var options = new DbContextOptionsBuilder<MedSignDb>()
            .UseSqlite($"Data Source=file:{Guid.NewGuid():n}?mode=memory&cache=shared")
            .Options;

        var db = new MedSignDb(options);
        db.Database.OpenConnection();
        db.Database.EnsureCreated();
        return db;
    }

    public static User Doctor() => new()
    {
        Id = 7,
        Username = "h.novak",
        Handle = [1, 2, 3, 4],
        DisplayName = "Dr. Helena Novak",
        Role = Roles.Doctor,
    };

    public static PasskeyCredential Credential(
        byte[] credentialId,
        byte[] publicKeyPoint,
        long signCount = 0) => new()
    {
        CredentialId = credentialId,
        PublicKeyPoint = publicKeyPoint,
        SignCount = signCount,
        Transports = "internal",
        CreatedAt = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
    };
}

public sealed class Lab
{
    public const string Origin = "http://localhost:4200";

    public const string ForeignOrigin = "https://medsign-clone.example";

    public const string RpId = "localhost";

    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(5);

    public Lab()
    {
        Fido2 = new Fido2(new Fido2Configuration
        {
            ServerDomain = RpId,
            ServerName = "MedSign Cloud",
            Origins = new HashSet<string>(StringComparer.Ordinal) { Origin },
            Timeout = 120_000,
            ChallengeSize = 32,
        });

        Clock = new TestClock();
        Challenges = new PasskeyChallengeStore(
            Build.Options(new PasskeyOptions { ChallengeLifetime = ChallengeLifetime }),
            Clock);
        Db = Build.Database();
        Passkeys = new MedSignPasskeys(Fido2, Challenges, Db);
    }

    public IFido2 Fido2 { get; }

    public TestClock Clock { get; }

    public PasskeyChallengeStore Challenges { get; }

    public MedSignDb Db { get; }

    public MedSignPasskeys Passkeys { get; }

    public User Enrol(
        VirtualAuthenticator authenticator,
        string username = "h.novak",
        long signCount = 0)
    {
        var user = new User
        {
            Username = username,
            Handle = RandomNumberGenerator.GetBytes(32),
            DisplayName = "Dr. Helena Novak",
            Role = Roles.Doctor,
            Credentials =
            [
                Build.Credential(authenticator.CredentialId, authenticator.PublicKeyPoint, signCount),
            ],
        };

        Db.Users.Add(user);
        Db.SaveChanges();

        return user;
    }
}

public static class Exercise
{
    private const string Pending = "Not implemented yet -- this is the exercise.";

    public static T OrSkip<T>(Func<T> act)
    {
        try
        {
            return act();
        }
        catch (NotImplementedException)
        {
            Assert.Skip(Pending);
            throw;
        }
    }

    public static async Task<T> OrSkipAsync<T>(Func<Task<T>> act)
    {
        try
        {
            return await act();
        }
        catch (NotImplementedException)
        {
            Assert.Skip(Pending);
            throw;
        }
    }

    public static TException ThrowsOrSkip<TException>(Action act) where TException : Exception
    {
        try
        {
            act();
        }
        catch (NotImplementedException)
        {
            Assert.Skip(Pending);
            throw;
        }
        catch (TException expected)
        {
            return expected;
        }
        catch (Exception actual)
        {
            Assert.Fail($"Expected {typeof(TException).Name}, got {actual.GetType().Name}: {actual.Message}");
        }

        Assert.Fail($"Expected {typeof(TException).Name}, but no exception was thrown.");
        throw new InvalidOperationException("Assert.Fail always throws.");
    }

    public static async Task<bool> RefusedOrSkipAsync<T>(Func<Task<T?>> act) where T : class
    {
        try
        {
            return await act() is null;
        }
        catch (NotImplementedException)
        {
            Assert.Skip(Pending);
            throw;
        }
        catch (Exception exception) when (IsCrash(exception))
        {
            Assert.Fail(
                $"MedSign crashed instead of refusing: {exception.GetType().Name}: {exception.Message}\n"
                + "Turning a ceremony down is a decision this method makes -- hand back null, or let "
                + "Fido2NetLib's verification exception through. Reaching this line means something was "
                + "read before it was checked.\n"
                + exception.StackTrace);
            return false;
        }
        catch (Exception)
        {
            return true;
        }
    }

    private static bool IsCrash(Exception exception) => exception
        is NullReferenceException
        or IndexOutOfRangeException
        or KeyNotFoundException
        or ObjectDisposedException
        or StackOverflowException;
}
