using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Data;
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
    public static T OrSkip<T>(Func<T> act)
    {
        try
        {
            return act();
        }
        catch (NotImplementedException)
        {
            Assert.Skip("Not implemented yet -- this is the exercise.");
            throw; // Unreachable: Assert.Skip does not return.
        }
    }
}
