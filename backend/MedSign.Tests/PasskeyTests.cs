using System.Security.Cryptography;
using Fido2NetLib;
using Fido2NetLib.Objects;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Lab;

namespace MedSign.Tests;

/// <summary>
/// A challenge is single-use and short-lived. Both properties are what stop a
/// captured ceremony from being replayed, so they are worth pinning down.
/// </summary>
public class PasskeyChallengeStoreTests
{
    /// <summary>A ceremony with every required member filled in; the values do not matter here.</summary>
    private static CredentialCreateOptions Ceremony() => new()
    {
        Rp = new PublicKeyCredentialRpEntity("localhost", "MedSign Cloud", null),
        User = new Fido2User
        {
            Id = RandomNumberGenerator.GetBytes(32),
            Name = "h.novak",
            DisplayName = "Dr. Helena Novak",
        },
        Challenge = RandomNumberGenerator.GetBytes(32),
        PubKeyCredParams = [PubKeyCredParam.ES256],
    };

    private static PasskeyChallengeStore Store(TimeProvider clock, TimeSpan? lifetime = null) =>
        new(Build.Options(new PasskeyOptions
        {
            ChallengeLifetime = lifetime ?? TimeSpan.FromMinutes(5),
        }), clock);

    [Fact]
    public void Hands_back_the_ceremony_it_was_given()
    {
        var store = Store(new TestClock());
        var ceremony = Ceremony();

        store.Issue("h.novak", ceremony);

        Assert.Same(ceremony, store.ConsumeRegistration("h.novak"));
    }

    [Fact]
    public void Will_not_hand_the_same_challenge_out_twice()
    {
        var store = Store(new TestClock());
        store.Issue("h.novak", Ceremony());

        store.ConsumeRegistration("h.novak");

        Assert.Null(store.ConsumeRegistration("h.novak"));
    }

    [Fact]
    public void Drops_a_challenge_once_it_has_expired()
    {
        var clock = new TestClock();
        var store = Store(clock, TimeSpan.FromMinutes(5));
        store.Issue("h.novak", Ceremony());

        clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));

        Assert.Null(store.ConsumeRegistration("h.novak"));
    }

    [Fact]
    public void Keeps_registration_and_sign_in_ceremonies_apart()
    {
        var store = Store(new TestClock());
        store.Issue("h.novak", Ceremony());

        Assert.Null(store.ConsumeAssertion("h.novak"));
        Assert.NotNull(store.ConsumeRegistration("h.novak"));
    }

    [Fact]
    public void Keeps_one_account_from_consuming_another_accounts_challenge()
    {
        var store = Store(new TestClock());
        store.Issue("h.novak", Ceremony());

        Assert.Null(store.ConsumeRegistration("someone.else"));
    }
}

/// <summary>
/// Exercise 1 -- MedSignPasskeys.BeginRegistration.
///
/// These skip while the method still throws NotImplementedException, so an
/// exercise you have not started never stops the backend. Once you write the
/// implementation they run for real.
/// </summary>
public class ExerciseOneBeginRegistrationTests
{
    private static MedSignPasskeys Subject(out PasskeyChallengeStore challenges)
    {
        var fido2 = new Fido2(new Fido2Configuration
        {
            ServerDomain = "localhost",
            ServerName = "MedSign Cloud",
            Origins = new HashSet<string>(StringComparer.Ordinal) { "http://localhost:4200" },
            Timeout = 120_000,
            ChallengeSize = 32,
        });

        challenges = new PasskeyChallengeStore(
            Build.Options(new PasskeyOptions()), new TestClock());

        return new MedSignPasskeys(fido2, challenges, Build.Database());
    }

    [Fact]
    public void Asks_the_browser_for_a_new_credential_on_this_relying_party()
    {
        var passkeys = Subject(out _);

        var options = Exercise.OrSkip(() => passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));

        Assert.Equal("localhost", options.Rp.Id);
        Assert.Equal("h.novak", options.User.Name);
        Assert.Equal("Dr. Helena Novak", options.User.DisplayName);
    }

    [Fact]
    public void Issues_a_fresh_random_challenge_and_user_handle()
    {
        var passkeys = Subject(out _);

        var first = Exercise.OrSkip(() => passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));
        var second = passkeys.BeginRegistration("h.novak", "Dr. Helena Novak");

        Assert.Equal(32, first.Challenge.Length);
        Assert.NotEqual(first.Challenge, second.Challenge);
        Assert.NotEqual(first.User.Id, second.User.Id);
    }

    [Fact]
    public void Asks_for_ES256_because_that_is_what_MedSign_verifies()
    {
        var passkeys = Subject(out _);

        var options = Exercise.OrSkip(() => passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));

        Assert.Contains(options.PubKeyCredParams, param => param.Alg == COSE.Algorithm.ES256);
    }

    [Fact]
    public void Remembers_the_ceremony_so_the_answer_can_be_checked_against_it()
    {
        var passkeys = Subject(out var challenges);

        var options = Exercise.OrSkip(() => passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));

        var held = challenges.ConsumeRegistration("h.novak");

        Assert.NotNull(held);
        Assert.Equal(options.Challenge, held.Challenge);
    }
}
