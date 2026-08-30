using System.Net;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Tests;

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

public class ExerciseFourRegistrationTests
{
    private const string Username = "h.novak";

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

        Assert.Null(PasskeyDiagnostics.DiagnoseRegistration(
            new VerifiedCredential(stored.CredentialId, stored.PublicKeyPoint, (uint)stored.SignCount)));
    }

    [Fact]
    public async Task Refuses_a_passkey_that_another_account_already_holds()
    {
        using var host = new MedSignHost();
        using var key = new VirtualAuthenticator();

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

public class ExerciseEightSignInTests
{
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
