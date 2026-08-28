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
    [Fact]
    public void Asks_the_browser_for_a_new_credential_on_this_relying_party()
    {
        var lab = new Lab();

        var options = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));

        Assert.Equal(Lab.RpId, options.Rp.Id);
        Assert.Equal("h.novak", options.User.Name);
        Assert.Equal("Dr. Helena Novak", options.User.DisplayName);
    }

    [Fact]
    public void Issues_a_fresh_random_challenge_and_user_handle()
    {
        var lab = new Lab();

        var first = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));
        var second = lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak");

        Assert.Equal(32, first.Challenge.Length);
        Assert.NotEqual(first.Challenge, second.Challenge);
        Assert.NotEqual(first.User.Id, second.User.Id);
    }

    [Fact]
    public void Asks_for_ES256_because_that_is_what_MedSign_verifies()
    {
        var lab = new Lab();

        var options = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));

        Assert.Contains(options.PubKeyCredParams, param => param.Alg == COSE.Algorithm.ES256);
    }

    [Fact]
    public void Remembers_the_ceremony_so_the_answer_can_be_checked_against_it()
    {
        var lab = new Lab();

        var options = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));

        var held = lab.Challenges.ConsumeRegistration("h.novak");

        Assert.NotNull(held);
        Assert.Equal(options.Challenge, held.Challenge);
    }
}

/// <summary>
/// Exercise 1 -- MedSignPasskeys.CompleteRegistrationAsync.
///
/// A real authenticator answers here: VirtualAuthenticator builds the same
/// attestation object a browser would post back, so Fido2NetLib verifies it for
/// real and a wrong answer is refused for the right reason.
/// </summary>
public class ExerciseOneCompleteRegistrationTests
{
    private const string Username = "h.novak";
    private const string FullName = "Dr. Helena Novak";

    [Fact]
    public async Task Records_the_credential_the_browser_just_made()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        var registered = await Exercise.OrSkipAsync(
            () => lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony)));

        Assert.Equal(key.CredentialId, registered.Credential.CredentialId);
        Assert.Equal(key.PublicKeyPoint, registered.Credential.PublicKeyPoint);
    }

    [Fact]
    public async Task Hands_back_a_public_key_in_the_shape_MedSign_stores()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        var registered = await Exercise.OrSkipAsync(
            () => lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony)));

        // The same check the endpoint runs before it opens an account, so a failure
        // here reads exactly like the error a participant would hit there.
        Assert.Null(PasskeyDiagnostics.DiagnoseRegistration(registered.Credential));
    }

    [Fact]
    public async Task Keeps_the_user_handle_the_ceremony_invented()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        var registered = await Exercise.OrSkipAsync(
            () => lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony)));

        // The account is keyed by this afterwards, so it has to be the handle
        // MedSign chose and not anything that came back off the wire.
        Assert.Equal(ceremony.User.Id, registered.UserHandle);
    }

    [Fact]
    public async Task Will_not_take_the_same_answer_twice()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));
        var answer = key.Register(ceremony);

        await Exercise.OrSkipAsync(() => lab.Passkeys.CompleteRegistrationAsync(Username, answer));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, answer)));
    }

    [Fact]
    public async Task Will_not_take_an_answer_to_a_ceremony_it_never_held()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));
        var answer = key.Register(ceremony);

        // The ceremony was issued to h.novak; nobody else may spend it.
        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync("someone.else", answer)));
    }

    [Fact]
    public async Task Will_not_take_an_answer_produced_on_another_site()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator { Origin = "http://localhost:4300" };

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony))));
    }

    [Fact]
    public async Task Will_not_take_a_credential_id_that_is_already_registered()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        // Somebody else already holds this credential. Only MedSign knows that --
        // the library has to be told to ask.
        lab.Enrol(key, "someone.else");

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony))));
    }
}

/// <summary>
/// Exercise 1 -- MedSignPasskeys.BeginSignInAsync.
/// </summary>
public class ExerciseOneBeginSignInTests
{
    [Fact]
    public async Task Names_this_relying_party_and_a_fresh_challenge()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var first = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var second = await lab.Passkeys.BeginSignInAsync(account.Username);

        Assert.Equal(Lab.RpId, first.RpId);
        Assert.Equal(32, first.Challenge.Length);
        Assert.NotEqual(first.Challenge, second.Challenge);
    }

    [Fact]
    public async Task Offers_the_credentials_this_account_actually_registered()
    {
        var lab = new Lab();
        using var phone = new VirtualAuthenticator();
        using var securityKey = new VirtualAuthenticator();

        var account = lab.Enrol(phone);
        account.Credentials.Add(Build.Credential(securityKey.CredentialId, securityKey.PublicKeyPoint));
        lab.Db.SaveChanges();

        var options = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        var allowed = options.AllowCredentials.Select(credential => credential.Id).ToList();

        Assert.Equal(2, allowed.Count);
        Assert.Contains(allowed, id => id.SequenceEqual(phone.CredentialId));
        Assert.Contains(allowed, id => id.SequenceEqual(securityKey.CredentialId));
    }

    [Fact]
    public async Task Remembers_the_ceremony_so_the_answer_can_be_checked_against_it()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var options = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        var held = lab.Challenges.ConsumeAssertion(account.Username);

        Assert.NotNull(held);
        Assert.Equal(options.Challenge, held.Challenge);
    }

    [Fact]
    public async Task Answers_an_unknown_username_the_same_way_as_a_known_one()
    {
        var lab = new Lab();

        // Nobody is enrolled here. A challenge still has to come back, and it still
        // has to be held: if MedSign refused early, the sign-in page would become a
        // way to ask which doctors have accounts.
        var options = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync("nobody.here"));

        Assert.Equal(32, options.Challenge.Length);
        Assert.Empty(options.AllowCredentials);
        Assert.NotNull(lab.Challenges.ConsumeAssertion("nobody.here"));
    }
}

/// <summary>
/// Exercise 1 -- MedSignPasskeys.CompleteSignInAsync.
///
/// The account is enrolled straight into the database rather than through the
/// registration exercise, so a failure here is about this method and nothing else.
/// </summary>
public class ExerciseOneCompleteSignInTests
{
    [Fact]
    public async Task Accepts_the_signature_the_registered_key_produced()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        var verified = await Exercise.OrSkipAsync(() => lab.Passkeys.CompleteSignInAsync(
            account.Username, key.SignIn(ceremony, account.Handle)));

        Assert.NotNull(verified);
        Assert.Equal(account.Username, verified.Account.Username);
        Assert.Equal(key.CredentialId, verified.Credential.CredentialId);
        Assert.Equal(key.SignCount, verified.SignCount);
    }

    [Fact]
    public async Task Turns_down_a_counter_that_has_gone_backwards()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        // The stored counter is far ahead of the one now answering, which is what a
        // cloned authenticator looks like from here.
        var account = lab.Enrol(key, signCount: 500);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, key.SignIn(ceremony, account.Handle))));
    }

    [Fact]
    public async Task Turns_down_an_assertion_answering_another_accounts_challenge()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync("someone.else"));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, key.SignIn(ceremony, account.Handle))));
    }

    [Fact]
    public async Task Will_not_let_the_same_assertion_be_replayed()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var answer = key.SignIn(ceremony, account.Handle);

        await Exercise.OrSkipAsync(() => lab.Passkeys.CompleteSignInAsync(account.Username, answer));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, answer)));
    }

    [Fact]
    public async Task Turns_down_an_account_that_does_not_exist()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync("nobody.here"));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(
                "nobody.here", key.SignIn(ceremony, [1, 2, 3, 4]))));
    }

    [Fact]
    public async Task Turns_down_a_credential_this_account_never_registered()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        using var stranger = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(
                account.Username, stranger.SignIn(ceremony, account.Handle))));
    }

    [Fact]
    public async Task Turns_down_a_signature_from_a_different_key()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        // The right credential id, a key MedSign never saw. Only the stored public
        // key tells the two apart.
        using var impostor = new VirtualAuthenticator { CredentialId = key.CredentialId };

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(
                account.Username, impostor.SignIn(ceremony, account.Handle))));
    }

    [Fact]
    public async Task Turns_down_a_user_handle_belonging_to_another_account()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(
                account.Username, key.SignIn(ceremony, RandomNumberGenerator.GetBytes(32)))));
    }

    [Fact]
    public async Task Turns_down_a_sign_in_with_no_assertion_at_all()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, null)));
    }
}
