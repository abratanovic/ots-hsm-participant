using System.Net;
using MedSign.Api.Auth;
using MedSign.Api.Passkeys;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Tests;

/// <summary>
/// Exercise 2 -- POST /api/auth/registration-challenge.
///
/// The ceremony method decides what MedSign asks the authenticator for. This
/// endpoint decides who is allowed to ask, and gets the answer onto the wire in
/// a shape the browser's WebAuthn call will accept.
/// </summary>
public class ExerciseTwoRegistrationChallengeTests
{
    private const string Username = "h.novak";

    [Fact]
    public async Task Hands_the_browser_a_ceremony_it_can_answer()
    {
        using var host = new MedSignHost();
        var client = host.CreateClient();

        var answer = (await client.PostAsync(Api.RegistrationChallenge, Api.Account(Username))).OrSkip();

        Assert.Equal(HttpStatusCode.OK, answer.Status);

        // Binary has to arrive as base64url -- navigator.credentials.create cannot
        // read anything else, and a byte array serialised as JSON numbers is the
        // usual way this goes wrong.
        Assert.Equal(32, answer.Bytes("challenge").Length);
        Assert.Equal(Lab.RpId, answer.Field("rp")?.GetProperty("id").GetString());
        Assert.Equal(Username, answer.Field("user")?.GetProperty("name").GetString());
        Assert.NotNull(answer.Field("pubKeyCredParams"));
        Assert.NotNull(answer.Field("authenticatorSelection"));
        Assert.NotNull(answer.Field("excludeCredentials"));
    }

    [Fact]
    public async Task Refuses_a_username_that_already_has_an_account()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        host.Enrol(key, Username);

        var answer = (await host.CreateClient()
            .PostAsync(Api.RegistrationChallenge, Api.Account(Username))).OrSkip();

        // Handing out a ceremony here would let the sign-up form answer "does this
        // doctor already have an account?" for anyone who asks.
        Assert.Equal(HttpStatusCode.Conflict, answer.Status);
    }

    [Fact]
    public async Task Issues_a_different_ceremony_to_every_caller()
    {
        using var host = new MedSignHost();
        var client = host.CreateClient();

        var first = (await client.PostAsync(Api.RegistrationChallenge, Api.Account(Username))).OrSkip();
        var second = await client.PostAsync(Api.RegistrationChallenge, Api.Account(Username));

        Assert.NotEqual(first.Bytes("challenge"), second.Bytes("challenge"));
        Assert.NotEqual(
            first.Field("user")?.GetProperty("id").GetString(),
            second.Field("user")?.GetProperty("id").GetString());
    }
}

/// <summary>
/// Exercise 4 -- POST /api/auth/registration.
///
/// A real authenticator answers the ceremony this endpoint handed out, so what
/// is verified here is verified for real, and what ends up in the database is
/// what a later sign-in will have to work from.
/// </summary>
public class ExerciseFourRegistrationTests
{
    private const string Username = "h.novak";

    /// <summary>Asks for a ceremony and answers it, the way the browser would.</summary>
    private static async Task<(Answer Ceremony, PasskeyRegistration Answer)> AnswerAsync(
        MedSignHost host, VirtualAuthenticator key, string username = Username)
    {
        var ceremony = (await host.CreateClient()
            .PostAsync(Api.RegistrationChallenge, Api.Account(username))).OrSkip();

        return (ceremony, key.Register(ceremony.Bytes("challenge"), Lab.RpId));
    }

    [Fact]
    public async Task Opens_an_account_for_a_passkey_it_verified()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();

        var (ceremony, answer) = await AnswerAsync(host, key);

        var session = (await host.CreateClient()
            .PostAsync(Api.Registration, Api.Registration_(Username, answer))).OrSkip();

        Assert.Equal(HttpStatusCode.OK, session.Status);
        Assert.False(string.IsNullOrWhiteSpace(session.Text("token")));
        Assert.Equal(Username, session.Field("user")?.GetProperty("username").GetString());

        var stored = host.Read(db => db.Users.Include(u => u.Credentials).Single());

        Assert.Equal(key.CredentialId, stored.Credentials.Single().CredentialId);
        Assert.Equal(key.PublicKeyPoint, stored.Credentials.Single().PublicKeyPoint);

        // The account is found by this handle on every later sign-in, so it has to
        // be the one the ceremony invented rather than anything off the wire.
        Assert.Equal(ceremony.Bytes2("user", "id"), stored.Handle);
    }

    [Fact]
    public async Task Stores_a_public_key_a_later_sign_in_can_verify_against()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();

        var (_, answer) = await AnswerAsync(host, key);

        (await host.CreateClient().PostAsync(Api.Registration, Api.Registration_(Username, answer))).OrSkip();

        var stored = host.Read(db => db.Users.Include(u => u.Credentials).Single().Credentials.Single());

        // The same check the endpoint runs, so a failure reads like the error a
        // participant would hit rather than a byte comparison.
        Assert.Null(PasskeyDiagnostics.DiagnoseRegistration(
            new VerifiedCredential(stored.CredentialId, stored.PublicKeyPoint, (uint)stored.SignCount)));
    }

    [Fact]
    public async Task Refuses_a_passkey_that_another_account_already_holds()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();

        // Somebody else enrolled this authenticator already. Only MedSign knows
        // that; the library has to be told to ask.
        host.Enrol(key, "m.kovac");

        var (_, answer) = await AnswerAsync(host, key);

        var session = (await host.CreateClient()
            .PostAsync(Api.Registration, Api.Registration_(Username, answer))).OrSkip();

        Assert.Equal(HttpStatusCode.Conflict, session.Status);
        Assert.Equal(1, host.Read(db => db.Users.Count()));
    }

    [Fact]
    public async Task Refuses_a_username_claimed_while_the_ceremony_was_open()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        using var other = new VirtualAuthenticator();

        var (_, answer) = await AnswerAsync(host, key);

        // The check on the challenge endpoint is not enough on its own: two people
        // can hold a ceremony for the same username at once.
        host.Enrol(other, Username);

        var session = (await host.CreateClient()
            .PostAsync(Api.Registration, Api.Registration_(Username, answer))).OrSkip();

        Assert.Equal(HttpStatusCode.Conflict, session.Status);
        Assert.Equal(1, host.Read(db => db.Users.Count()));
    }

    [Fact]
    public async Task Refuses_an_answer_produced_on_another_site()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator { Origin = Lab.ForeignOrigin };

        var (_, answer) = await AnswerAsync(host, key);

        var session = (await host.CreateClient()
            .PostAsync(Api.Registration, Api.Registration_(Username, answer))).OrSkip();

        Assert.True(session.Refused());
        Assert.Equal(0, host.Read(db => db.Users.Count()));
    }

    [Fact]
    public async Task Will_not_open_two_accounts_from_one_ceremony()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var client = host.CreateClient();

        var (_, answer) = await AnswerAsync(host, key);

        (await client.PostAsync(Api.Registration, Api.Registration_(Username, answer))).OrSkip();

        var replay = await client.PostAsync(Api.Registration, Api.Registration_("someone.else", answer));

        Assert.True(replay.Refused());
        Assert.Equal(1, host.Read(db => db.Users.Count()));
    }
}

/// <summary>
/// Exercise 6 -- POST /api/auth/sign-in-challenge.
///
/// This endpoint is asked a username by anyone who can reach it, so what it
/// gives back has to be useful to the person holding the passkey and useless to
/// everybody else.
/// </summary>
public class ExerciseSixSignInChallengeTests
{
    [Fact]
    public async Task Names_the_credentials_that_may_answer()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var account = host.Enrol(key);

        var answer = (await host.CreateClient()
            .PostAsync(Api.SignInChallenge, new { username = account.Username })).OrSkip();

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.Equal(32, answer.Bytes("challenge").Length);
        Assert.Equal(Lab.RpId, answer.Text("rpId"));
        Assert.Contains(Base64Url.Encode(key.CredentialId), answer.Raw);
    }

    [Fact]
    public async Task Answers_an_unknown_username_without_saying_so()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var account = host.Enrol(key);
        var client = host.CreateClient();

        var known = (await client.PostAsync(Api.SignInChallenge, new { username = account.Username })).OrSkip();
        var unknown = (await client.PostAsync(Api.SignInChallenge, new { username = "nobody.here" })).OrSkip();

        // Refusing here would turn the sign-in page into a way to ask which doctors
        // have accounts. A challenge comes back either way.
        Assert.Equal(known.Status, unknown.Status);
        Assert.Equal(32, unknown.Bytes("challenge").Length);
        Assert.DoesNotContain(Base64Url.Encode(key.CredentialId), unknown.Raw);
    }

    [Fact]
    public async Task Issues_a_fresh_challenge_every_time()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var account = host.Enrol(key);
        var client = host.CreateClient();

        var first = (await client.PostAsync(Api.SignInChallenge, new { username = account.Username })).OrSkip();
        var second = await client.PostAsync(Api.SignInChallenge, new { username = account.Username });

        Assert.NotEqual(first.Bytes("challenge"), second.Bytes("challenge"));
    }
}

/// <summary>
/// Exercise 8 -- POST /api/auth/sign-in.
///
/// The last step, and the one that hands out a session. Everything the ceremony
/// method verified is only worth something if this endpoint acts on it: the new
/// counter has to survive the request, and a refusal must not say why.
/// </summary>
public class ExerciseEightSignInTests
{
    /// <summary>Asks for a ceremony and signs it, the way the browser would.</summary>
    private static async Task<PasskeyAssertion> AnswerAsync(
        MedSignHost host, VirtualAuthenticator key, string username, byte[]? handle)
    {
        var ceremony = (await host.CreateClient()
            .PostAsync(Api.SignInChallenge, new { username })).OrSkip();

        return key.SignIn(ceremony.Bytes("challenge"), Lab.RpId, handle);
    }

    [Fact]
    public async Task Signs_in_the_account_that_owns_the_passkey()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var account = host.Enrol(key);

        var assertion = await AnswerAsync(host, key, account.Username, account.Handle);

        var session = (await host.CreateClient()
            .PostAsync(Api.SignIn, Api.SignIn_(account.Username, assertion))).OrSkip();

        Assert.Equal(HttpStatusCode.OK, session.Status);
        Assert.False(string.IsNullOrWhiteSpace(session.Text("token")));
        Assert.Equal(account.Username, session.Field("user")?.GetProperty("username").GetString());
    }

    [Fact]
    public async Task Saves_the_counter_the_authenticator_just_reported()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var account = host.Enrol(key);

        var assertion = await AnswerAsync(host, key, account.Username, account.Handle);

        (await host.CreateClient().PostAsync(Api.SignIn, Api.SignIn_(account.Username, assertion))).OrSkip();

        // A counter that is never written back is a clone check that never fires:
        // the stored value stays at 0 and every replayed assertion clears it.
        Assert.Equal(key.SignCount, (uint)host.Read(
            db => db.Users.Include(u => u.Credentials).Single().Credentials.Single().SignCount));
    }

    [Fact]
    public async Task Turns_down_a_signature_from_a_key_it_never_registered()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        using var impostor = new VirtualAuthenticator { CredentialId = key.CredentialId };
        var account = host.Enrol(key);

        var assertion = await AnswerAsync(host, impostor, account.Username, account.Handle);

        var session = (await host.CreateClient()
            .PostAsync(Api.SignIn, Api.SignIn_(account.Username, assertion))).OrSkip();

        Assert.Equal(HttpStatusCode.Unauthorized, session.Status);
    }

    [Fact]
    public async Task Turns_down_a_replayed_assertion()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var account = host.Enrol(key);
        var client = host.CreateClient();

        var assertion = await AnswerAsync(host, key, account.Username, account.Handle);

        (await client.PostAsync(Api.SignIn, Api.SignIn_(account.Username, assertion))).OrSkip();

        var replay = await client.PostAsync(Api.SignIn, Api.SignIn_(account.Username, assertion));

        Assert.Equal(HttpStatusCode.Unauthorized, replay.Status);
    }

    [Fact]
    public async Task Answers_every_refusal_the_same_way()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        using var stranger = new VirtualAuthenticator();
        var account = host.Enrol(key);
        var client = host.CreateClient();

        var wrongKey = await AnswerAsync(host, stranger, account.Username, account.Handle);
        var unknownAccount = await AnswerAsync(host, key, "nobody.here", account.Handle);
        var noCeremony = key.SignIn(new byte[32], Lab.RpId, account.Handle);

        var refusals = new[]
        {
            await client.PostAsync(Api.SignIn, Api.SignIn_(account.Username, wrongKey)),
            await client.PostAsync(Api.SignIn, Api.SignIn_("nobody.here", unknownAccount)),
            await client.PostAsync(Api.SignIn, Api.SignIn_(account.Username, noCeremony)),
        };

        // A credential MedSign has never seen, an account that does not exist, and
        // an answer to no ceremony at all. Told apart from the outside, these say
        // which usernames are real and which passkeys MedSign knows -- so all three
        // get one answer, and it carries no detail.
        foreach (var refusal in refusals)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, refusal.OrSkip().Status);
            Assert.Equal(refusals[0].Raw, refusal.Raw);
            Assert.Null(refusal.Field("detail"));
        }
    }

    [Fact]
    public async Task Turns_down_a_sign_in_with_no_assertion_at_all()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();
        var account = host.Enrol(key);

        await AnswerAsync(host, key, account.Username, account.Handle);

        var session = await host.CreateClient()
            .PostAsync(Api.SignIn, Api.SignIn_(account.Username, null));

        Assert.True(session.Refused());
    }
}
