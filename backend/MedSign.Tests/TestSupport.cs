using System.Security.Cryptography;
using Fido2NetLib;
using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Data;
using MedSign.Api.Lab;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace MedSign.Tests;

/// <summary>A clock the test moves by hand, so nothing here waits on wall time.</summary>
public sealed class TestClock(DateTimeOffset now) : TimeProvider
{
    private DateTimeOffset _now = now;

    public TestClock() : this(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero))
    {
    }

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}

/// <summary>
/// A throwaway directory that deletes itself. EnvFileSigningProvider writes a real
/// .env, so the tests give it a real -- but disposable -- content root.
/// </summary>
public sealed class TempContentRoot : IHostEnvironment, IDisposable
{
    public TempContentRoot()
    {
        ContentRootPath = Path.Combine(Path.GetTempPath(), "medsign-tests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(ContentRootPath);
    }

    public string EnvironmentName { get; set; } = Environments.Development;
    public string ApplicationName { get; set; } = "MedSign.Tests";
    public string ContentRootPath { get; set; }
    public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();

    public string EnvPath => Path.Combine(ContentRootPath, ".env");

    public void Dispose()
    {
        try
        {
            Directory.Delete(ContentRootPath, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }
}

public static class Build
{
    public static IOptions<T> Options<T>(T value) where T : class => Microsoft.Extensions.Options.Options.Create(value);

    /// <summary>An empty SQLite database, held open for the lifetime of the connection.</summary>
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

    /// <summary>A stored passkey, shaped the way a finished registration leaves it.</summary>
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

/// <summary>
/// MedSignPasskeys wired the way Program.cs wires it, with the pieces around it
/// left reachable so a test can look at what the exercise did: the challenge
/// store it was supposed to hold the ceremony in, and the database it was
/// supposed to consult.
/// </summary>
public sealed class Lab
{
    /// <summary>The one origin the relying party accepts; anything else is a different site.</summary>
    public const string Origin = "http://localhost:4200";

    public const string RpId = "localhost";

    /// <summary>How long a held ceremony stays spendable; the tests move <see cref="Clock"/> past it.</summary>
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

    /// <summary>The clock the challenge store reads, so a test can let a held ceremony go stale.</summary>
    public TestClock Clock { get; }

    public PasskeyChallengeStore Challenges { get; }

    public MedSignDb Db { get; }

    public MedSignPasskeys Passkeys { get; }

    /// <summary>
    /// An account that already holds this authenticator's passkey -- the state the
    /// registration ceremony leaves behind, written straight to the database so the
    /// sign-in tests do not also depend on the registration exercise.
    /// </summary>
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

/// <summary>
/// Marks a test that checks work a participant has not done yet.
///
/// While the exercise still throws NotImplementedException the test reports as
/// skipped, so the gate lets the backend start -- you cannot be blocked by an
/// exercise you have not reached. The moment there is real code behind it the
/// exception stops coming, the assertions run for real, and a wrong
/// implementation now stops the backend like any other failure.
/// </summary>
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
            throw; // Unreachable: Assert.Skip does not return.
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
            throw; // Unreachable: Assert.Skip does not return.
        }
    }

    /// <summary>
    /// True when MedSign turned the ceremony down: either by handing back nothing,
    /// or by letting the library's verification exception through. Both are
    /// refusals, and which one a method gives depends on how it was written --
    /// what matters is that a ceremony MedSign cannot vouch for is never accepted.
    ///
    /// Crashing is not a refusal. A NullReferenceException (and friends) means the
    /// method walked off the end of its own happy path, which reaches the endpoint
    /// as a 500 rather than a rejected sign-in, so those are reported as failures
    /// with the exception that caused them.
    /// </summary>
    public static async Task<bool> RefusedOrSkipAsync<T>(Func<Task<T?>> act) where T : class
    {
        try
        {
            return await act() is null;
        }
        catch (NotImplementedException)
        {
            Assert.Skip(Pending);
            throw; // Unreachable: Assert.Skip does not return.
        }
        catch (Exception exception) when (IsCrash(exception))
        {
            Assert.Fail(
                $"MedSign crashed instead of refusing: {exception.GetType().Name}: {exception.Message}\n"
                + "Turning a ceremony down is a decision this method makes -- hand back null, or let "
                + "Fido2NetLib's verification exception through. Reaching this line means something was "
                + "read before it was checked.\n"
                + exception.StackTrace);
            return false; // Unreachable: Assert.Fail does not return.
        }
        catch (Exception)
        {
            return true;
        }
    }

    /// <summary>A bug dressed as a rejection: nothing here is a decision the method made.</summary>
    private static bool IsCrash(Exception exception) => exception
        is NullReferenceException
        or IndexOutOfRangeException
        or KeyNotFoundException
        or ObjectDisposedException
        or StackOverflowException;
}
