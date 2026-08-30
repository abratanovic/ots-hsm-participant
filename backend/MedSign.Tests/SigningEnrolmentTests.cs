using System.Net;
using System.Security.Cryptography;
using MedSign.Api.Hsm;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Tests;

public class SigningEnrolmentTests
{
    private static (MedSignHost Host, string Token) Doctor(string username = "h.novak")
    {
        var host = new MedSignHost();
        var doctor = host.Account(username, Roles.Doctor, "Dr. Helena Novak");

        return (host, host.TokenFor(doctor));
    }

    [Fact]
    public async Task Says_signing_is_not_set_up_before_a_doctor_enables_it()
    {
        var (host, token) = Doctor();
        using var owned = host;

        var answer = await owned.CreateClient().AskAsync(Api.SigningStatus, token);

        Assert.Equal(HttpStatusCode.OK, answer.Status);
        Assert.False(answer.Field("enabled")?.GetBoolean());

        Assert.Null(answer.Field("publicKeyFingerprint"));
    }

    [Fact]
    public async Task Makes_a_doctor_a_key_and_describes_it()
    {
        var (host, token) = Doctor();
        using var owned = host;
        var client = owned.CreateClient();

        var enabled = await client.PostAsync(Api.SigningEnable, token: token);

        Assert.Equal(HttpStatusCode.OK, enabled.Status);
        Assert.True(enabled.Field("enabled")?.GetBoolean());
        Assert.False(string.IsNullOrWhiteSpace(enabled.Text("publicKeyFingerprint")));
        Assert.NotNull(enabled.Field("createdAt"));

        var status = await client.AskAsync(Api.SigningStatus, token);

        Assert.Equal(enabled.Text("publicKeyFingerprint"), status.Text("publicKeyFingerprint"));
    }

    [Fact]
    public async Task Keeps_the_public_half_and_nothing_else()
    {
        var (host, token) = Doctor();
        using var owned = host;

        await owned.CreateClient().PostAsync(Api.SigningEnable, token: token);

        var stored = owned.Read(db => db.SigningKeys.Single());

        EcPoint.EnsureUncompressedP256(stored.PublicKeyPoint);

        var doctor = owned.Read(db => db.Users.Single(user => user.Username == "h.novak"));

        Assert.Equal(stored.Id, doctor.SigningKeyId);
    }

    [Fact]
    public async Task Enabling_twice_hands_back_the_same_key_rather_than_making_another()
    {
        var (host, token) = Doctor();
        using var owned = host;
        var client = owned.CreateClient();

        var first = await client.PostAsync(Api.SigningEnable, token: token);
        var second = await client.PostAsync(Api.SigningEnable, token: token);

        Assert.Equal(HttpStatusCode.OK, second.Status);
        Assert.Equal(first.Text("publicKeyFingerprint"), second.Text("publicKeyFingerprint"));

        Assert.Equal(1, owned.Read(db => db.SigningKeys.Count()));
    }

    [Fact]
    public async Task Re_adopts_a_key_the_device_still_holds_after_the_database_forgot_it()
    {
        var (host, token) = Doctor();
        using var owned = host;
        var client = owned.CreateClient();

        var first = await client.PostAsync(Api.SigningEnable, token: token);

        owned.Read(db =>
        {
            foreach (var user in db.Users)
            {
                user.SigningKeyId = null;
            }

            db.SigningKeys.RemoveRange(db.SigningKeys);

            return db.SaveChanges();
        });

        var again = await client.PostAsync(Api.SigningEnable, token: token);

        Assert.Equal(first.Text("publicKeyFingerprint"), again.Text("publicKeyFingerprint"));
    }

    [Fact]
    public async Task Labels_a_doctors_key_apart_from_the_applications_own_and_from_other_doctors()
    {
        var (host, token) = Doctor();
        using var owned = host;

        var colleague = owned.Account("i.babic", Roles.Doctor, "Dr. Ivan Babić");

        var mine = await owned.CreateClient().PostAsync(Api.SigningEnable, token: token);
        var theirs = await owned.CreateClient()
            .PostAsync(Api.SigningEnable, token: owned.TokenFor(colleague));

        Assert.NotEqual(mine.Text("publicKeyFingerprint"), theirs.Text("publicKeyFingerprint"));

        var labels = owned.Read(db => db.SigningKeys.Select(key => key.KeyLabel).ToList());
        var jwtLabel = owned.Read(db => db.JwtSigningKeys.Single().Label);

        Assert.Equal(2, labels.Distinct().Count());
        Assert.DoesNotContain(jwtLabel, labels);
    }

    [Fact]
    public async Task Never_tells_the_caller_the_label_the_device_knows_the_key_by()
    {
        var (host, token) = Doctor();
        using var owned = host;
        var client = owned.CreateClient();

        var enabled = await client.PostAsync(Api.SigningEnable, token: token);
        var status = await client.AskAsync(Api.SigningStatus, token);

        var label = owned.Read(db => db.SigningKeys.Single().KeyLabel);

        Assert.Null(enabled.Field("keyLabel"));
        Assert.Null(status.Field("keyLabel"));
        Assert.DoesNotContain(label, enabled.Raw);
        Assert.DoesNotContain(label, status.Raw);
    }

    [Fact]
    public async Task Refuses_to_hand_a_doctor_the_label_the_application_signs_tokens_with()
    {
        using var host = new MedSignHost();

        host.Settings["Hsm:KeyLabel"] = DoctorKeyLabel.For(1);

        var doctor = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");

        Assert.Equal(1, doctor.Id);

        var answer = await host.CreateClient()
            .PostAsync(Api.SigningEnable, token: host.TokenFor(doctor));

        Assert.Equal(HttpStatusCode.Conflict, answer.Status);
        Assert.Equal(0, host.Read(db => db.SigningKeys.Count()));
    }

    [Fact]
    public async Task Refuses_a_patient_both_the_question_and_the_action()
    {
        using var host = new MedSignHost();
        var patient = host.Account("m.kovac", Roles.Patient, "Marko Kovač");
        var token = host.TokenFor(patient);
        var client = host.CreateClient();

        Assert.Equal(HttpStatusCode.Forbidden, (await client.AskAsync(Api.SigningStatus, token)).Status);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await client.PostAsync(Api.SigningEnable, token: token)).Status);

        Assert.Equal(0, host.Read(db => db.SigningKeys.Count()));
    }

    [Fact]
    public async Task Refuses_a_caller_with_no_session()
    {
        using var host = new MedSignHost();
        var client = host.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.AskAsync(Api.SigningStatus)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync(Api.SigningEnable)).Status);
    }

    [Fact]
    public async Task Says_the_device_is_unreachable_rather_than_failing_generically()
    {
        var (host, token) = Doctor();
        using var owned = host;

        owned.Hsm.Unavailable = true;

        var answer = await owned.CreateClient().PostAsync(Api.SigningEnable, token: token);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, answer.Status);
        Assert.Equal(Problem.ContentType, answer.ContentType);
        Assert.Equal(0, owned.Read(db => db.SigningKeys.Count()));
    }

    [Fact]
    public async Task Leaves_signing_off_when_the_device_could_not_make_the_key()
    {
        var (host, token) = Doctor();
        using var owned = host;
        var client = owned.CreateClient();

        owned.Hsm.Unavailable = true;
        await client.PostAsync(Api.SigningEnable, token: token);

        owned.Hsm.Unavailable = false;
        var status = await client.AskAsync(Api.SigningStatus, token);

        Assert.False(status.Field("enabled")?.GetBoolean());
    }
}

public class FakeDocumentSignerTests
{
    [Fact]
    public void Signs_a_digest_the_public_point_it_handed_out_can_verify()
    {
        using var signer = new FakeDocumentSigner();

        var point = signer.CreateKey("medsign-doctor-1");
        var digest = SHA256.HashData("a report"u8.ToArray());

        var signature = signer.SignDigest("medsign-doctor-1", digest);

        Assert.Equal(2 * Pkcs11Constants.P256CoordinateBytes, signature.Length);

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = EcPoint.X(point), Y = EcPoint.Y(point) },
        });

        Assert.True(ecdsa.VerifyHash(
            digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void Keeps_a_key_it_made_so_a_later_call_finds_it()
    {
        using var signer = new FakeDocumentSigner();

        var point = signer.CreateKey("medsign-doctor-1");

        Assert.Equal(point, signer.FindKey("medsign-doctor-1"));
        Assert.Null(signer.FindKey("medsign-doctor-2"));
    }

    [Fact]
    public void Lets_a_label_be_used_twice_and_then_cannot_tell_the_keys_apart()
    {
        using var signer = new FakeDocumentSigner();

        signer.CreateKey("medsign-doctor-1");
        signer.CreateKey("medsign-doctor-1");

        Assert.Throws<HsmUnavailableException>(() => signer.FindKey("medsign-doctor-1"));
    }
}
