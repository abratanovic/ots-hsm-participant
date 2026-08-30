using System.Security.Cryptography;
using Fido2NetLib;
using Fido2NetLib.Objects;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Tests;

public class PasskeyChallengeStoreTests
{
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

    [Fact]
    public void Holds_only_the_ceremony_that_was_issued_last()
    {
        var store = Store(new TestClock());
        store.Issue("h.novak", Ceremony());

        var second = Ceremony();
        store.Issue("h.novak", second);

        Assert.Same(second, store.ConsumeRegistration("h.novak"));
        Assert.Null(store.ConsumeRegistration("h.novak"));
    }

    [Fact]
    public void Keeps_a_challenge_up_to_the_last_moment_before_it_expires()
    {
        var clock = new TestClock();
        var store = Store(clock, TimeSpan.FromMinutes(5));
        store.Issue("h.novak", Ceremony());

        clock.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(1));

        Assert.NotNull(store.ConsumeRegistration("h.novak"));
    }

    [Fact]
    public void Treats_the_expiry_moment_itself_as_too_late()
    {
        var clock = new TestClock();
        var store = Store(clock, TimeSpan.FromMinutes(5));
        store.Issue("h.novak", Ceremony());

        clock.Advance(TimeSpan.FromMinutes(5));

        Assert.Null(store.ConsumeRegistration("h.novak"));
    }

    [Fact]
    public void Sweeping_an_expired_challenge_leaves_a_live_one_alone()
    {
        var clock = new TestClock();
        var store = Store(clock, TimeSpan.FromMinutes(5));
        store.Issue("h.novak", Ceremony());

        clock.Advance(TimeSpan.FromMinutes(4));
        store.Issue("m.kovac", Ceremony());

        clock.Advance(TimeSpan.FromMinutes(2));

        Assert.Null(store.ConsumeRegistration("h.novak"));
        Assert.NotNull(store.ConsumeRegistration("m.kovac"));
    }

    [Fact]
    public async Task Hands_a_challenge_to_exactly_one_caller_when_several_race_for_it()
    {
        var store = Store(new TestClock());
        store.Issue("h.novak", Ceremony());

        var winners = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ =>
            Task.Run(() => store.ConsumeRegistration("h.novak"))));

        Assert.Single(winners.Where(ceremony => ceremony is not null));
    }
}

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

    [Fact]
    public void Holds_the_ceremony_the_browser_was_actually_given()
    {
        var lab = new Lab();

        Exercise.OrSkip(() => lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));
        var second = lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak");

        var held = lab.Challenges.ConsumeRegistration("h.novak");

        Assert.NotNull(held);
        Assert.Equal(second.Challenge, held.Challenge);
        Assert.Equal(second.User.Id, held.User.Id);
    }

    [Fact]
    public void Fills_in_everything_the_endpoint_puts_on_the_wire()
    {
        var lab = new Lab();

        var options = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration("h.novak", "Dr. Helena Novak"));

        var wire = PasskeyWire.ToWire(options);

        Assert.Equal(Base64Url.Encode(options.Challenge), wire.Challenge);
        Assert.Equal(Lab.RpId, wire.Rp.Id);
        Assert.Equal("h.novak", wire.User.Name);
        Assert.NotEmpty(wire.PubKeyCredParams);
        Assert.NotNull(wire.AuthenticatorSelection);
        Assert.NotNull(wire.ExcludeCredentials);
        Assert.True(wire.Timeout > 0, "The browser needs a timeout it can count down.");
    }
}

public class ExerciseThreeCompleteRegistrationTests
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

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync("someone.else", answer)));
    }

    [Fact]
    public async Task Will_not_take_an_answer_produced_on_another_site()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator { Origin = Lab.ForeignOrigin };

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony))));
    }

    [Fact]
    public async Task Starts_the_counter_where_the_authenticator_has_it()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        var registered = await Exercise.OrSkipAsync(
            () => lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony)));

        Assert.Equal(key.SignCount, registered.Credential.SignCount);
    }

    [Fact]
    public async Task Will_not_take_an_answer_to_a_challenge_it_is_no_longer_holding()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var abandoned = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        lab.Passkeys.BeginRegistration(Username, FullName);

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(abandoned))));
    }

    [Fact]
    public async Task Will_not_take_an_answer_to_a_ceremony_that_has_gone_stale()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));
        var answer = key.Register(ceremony);

        lab.Clock.Advance(Lab.ChallengeLifetime + TimeSpan.FromSeconds(1));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, answer)));
    }

    [Fact]
    public async Task Will_not_take_a_credential_that_was_made_for_another_relying_party()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator { RpIdOverride = "medsign-clone.example" };

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony))));
    }

    [Fact]
    public async Task Will_not_take_a_sign_in_answer_dressed_up_as_a_registration()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator { ClientDataTypeOverride = "webauthn.get" };

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony))));
    }

    [Fact]
    public async Task Will_not_take_a_credential_id_that_is_already_registered()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

        lab.Enrol(key, "someone.else");

        var ceremony = Exercise.OrSkip(() => lab.Passkeys.BeginRegistration(Username, FullName));

        Assert.True(await Exercise.RefusedOrSkipAsync<RegisteredPasskey>(
            async () => await lab.Passkeys.CompleteRegistrationAsync(Username, key.Register(ceremony))));
    }
}

public class ExerciseFiveBeginSignInTests
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
    public async Task Offers_nothing_that_belongs_to_another_account()
    {
        var lab = new Lab();
        using var mine = new VirtualAuthenticator();
        using var theirs = new VirtualAuthenticator();

        var account = lab.Enrol(mine);
        lab.Enrol(theirs, "m.kovac");

        var options = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.Single(options.AllowCredentials);
        Assert.DoesNotContain(options.AllowCredentials, c => c.Id.SequenceEqual(theirs.CredentialId));
    }

    [Fact]
    public async Task Holds_the_ceremony_the_browser_was_actually_given()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var second = await lab.Passkeys.BeginSignInAsync(account.Username);

        var held = lab.Challenges.ConsumeAssertion(account.Username);

        Assert.NotNull(held);
        Assert.Equal(second.Challenge, held.Challenge);
    }

    [Fact]
    public async Task Fills_in_everything_the_endpoint_puts_on_the_wire()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var options = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        var wire = PasskeyWire.ToWire(options);

        Assert.Equal(Base64Url.Encode(options.Challenge), wire.Challenge);
        Assert.Equal(Lab.RpId, wire.RpId);
        Assert.True(wire.Timeout > 0, "The browser needs a timeout it can count down.");
        Assert.NotNull(wire.AllowCredentials);
        Assert.Contains(wire.AllowCredentials, c => c.Id == Base64Url.Encode(key.CredentialId));
    }

    [Fact]
    public async Task Answers_an_unknown_username_the_same_way_as_a_known_one()
    {
        var lab = new Lab();

        var options = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync("nobody.here"));

        Assert.Equal(32, options.Challenge.Length);
        Assert.Empty(options.AllowCredentials);
        Assert.NotNull(lab.Challenges.ConsumeAssertion("nobody.here"));
    }
}

public class ExerciseSevenCompleteSignInTests
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
    public async Task Hands_back_the_stored_rows_the_endpoint_is_about_to_write_to()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        var verified = await Exercise.OrSkipAsync(() => lab.Passkeys.CompleteSignInAsync(
            account.Username, key.SignIn(ceremony, account.Handle)));

        Assert.NotNull(verified);

        Assert.NotEqual(EntityState.Detached, lab.Db.Entry(verified.Credential).State);
        Assert.NotEqual(EntityState.Detached, lab.Db.Entry(verified.Account).State);
    }

    [Fact]
    public async Task Signs_in_with_whichever_of_this_accounts_keys_answered()
    {
        var lab = new Lab();
        using var phone = new VirtualAuthenticator();
        using var securityKey = new VirtualAuthenticator();

        var account = lab.Enrol(phone);
        account.Credentials.Add(Build.Credential(securityKey.CredentialId, securityKey.PublicKeyPoint));
        lab.Db.SaveChanges();

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        var verified = await Exercise.OrSkipAsync(() => lab.Passkeys.CompleteSignInAsync(
            account.Username, securityKey.SignIn(ceremony, account.Handle)));

        Assert.NotNull(verified);
        Assert.Equal(securityKey.CredentialId, verified.Credential.CredentialId);
    }

    [Fact]
    public async Task Accepts_the_next_sign_in_once_the_counter_has_been_saved()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var first = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        var once = await Exercise.OrSkipAsync(() => lab.Passkeys.CompleteSignInAsync(
            account.Username, key.SignIn(first, account.Handle)));

        Assert.NotNull(once);

        once.Credential.SignCount = once.SignCount;
        await lab.Db.SaveChangesAsync();

        var second = await lab.Passkeys.BeginSignInAsync(account.Username);
        var twice = await lab.Passkeys.CompleteSignInAsync(
            account.Username, key.SignIn(second, account.Handle));

        Assert.NotNull(twice);
        Assert.True(twice.SignCount > once.SignCount, "The counter has to keep climbing.");
    }

    [Fact]
    public async Task Turns_down_a_counter_that_has_not_moved()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key, signCount: 5);

        key.SignCount = 4;

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, key.SignIn(ceremony, account.Handle))));
    }

    [Fact]
    public async Task Turns_down_a_counter_that_has_gone_backwards()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();

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

    [Fact]
    public async Task Turns_down_a_sign_in_nobody_ever_asked_for()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var answer = key.SignIn(ceremony, account.Handle);

        lab.Challenges.ConsumeAssertion(account.Username);

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, answer)));
    }

    [Fact]
    public async Task Turns_down_an_assertion_once_the_challenge_has_gone_stale()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var answer = key.SignIn(ceremony, account.Handle);

        lab.Clock.Advance(Lab.ChallengeLifetime + TimeSpan.FromSeconds(1));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, answer)));
    }

    [Fact]
    public async Task Turns_down_an_assertion_whose_signature_was_altered_in_flight()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var answer = key.SignIn(ceremony, account.Handle);

        var tampered = answer with
        {
            Response = answer.Response with
            {
                Signature = VirtualAuthenticator.Flip(answer.Response.Signature, index: 5),
            },
        };

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, tampered)));
    }

    [Fact]
    public async Task Turns_down_an_assertion_whose_authenticator_data_was_altered_in_flight()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var answer = key.SignIn(ceremony, account.Handle);

        var tampered = answer with
        {
            Response = answer.Response with
            {
                AuthenticatorData = VirtualAuthenticator.Flip(answer.Response.AuthenticatorData),
            },
        };

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, tampered)));
    }

    [Fact]
    public async Task Turns_down_an_answer_produced_on_another_site()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator { Origin = Lab.ForeignOrigin };
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, key.SignIn(ceremony, account.Handle))));
    }

    [Fact]
    public async Task Turns_down_an_answer_signed_for_another_relying_party()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator { RpIdOverride = "medsign-clone.example" };
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, key.SignIn(ceremony, account.Handle))));
    }

    [Fact]
    public async Task Turns_down_a_registration_answer_replayed_as_a_sign_in()
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator { ClientDataTypeOverride = "webauthn.create" };
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, key.SignIn(ceremony, account.Handle))));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base64url!!")]
    [InlineData("AAAA")]
    public async Task Turns_down_a_credential_id_it_cannot_make_sense_of(string rawId)
    {
        var lab = new Lab();
        using var key = new VirtualAuthenticator();
        var account = lab.Enrol(key);

        var ceremony = await Exercise.OrSkipAsync(() => lab.Passkeys.BeginSignInAsync(account.Username));
        var answer = key.SignIn(ceremony, account.Handle);

        var bogus = answer with { Id = rawId, RawId = rawId };

        Assert.True(await Exercise.RefusedOrSkipAsync<VerifiedAssertion>(
            () => lab.Passkeys.CompleteSignInAsync(account.Username, bogus)));
    }
}
