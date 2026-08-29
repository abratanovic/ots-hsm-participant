using System.Net;
using System.Security.Cryptography;
using MedSign.Api.Hsm;
using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Tests;

/// <summary>
/// GET /api/signing/status and POST /api/signing/enable.
///
/// This is where the workshop's claim stops being about one shared server key
/// and starts being about a key that belongs to a person: a doctor asks for a
/// signing key, the device makes one that cannot be exported, and MedSign keeps
/// nothing but the public half.
///
/// The device itself cannot take part in a test -- there is no simulator and no
/// container for a YubiHSM -- so the host swaps in a fake that generates real
/// P-256 keys in software. Nothing below reaches for it except to unplug it.
/// </summary>
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

        // Nothing to describe yet, and the frontend reads a missing field as
        // "not set up" rather than rendering a placeholder.
        Assert.Null(answer.Field("keyLabel"));
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
        Assert.False(string.IsNullOrWhiteSpace(enabled.Text("keyLabel")));
        Assert.False(string.IsNullOrWhiteSpace(enabled.Text("publicKeyFingerprint")));
        Assert.NotNull(enabled.Field("createdAt"));

        // Asking again is the same answer: enrolment is a fact about the
        // account, not a receipt for the request that created it.
        var status = await client.AskAsync(Api.SigningStatus, token);

        Assert.Equal(enabled.Text("keyLabel"), status.Text("keyLabel"));
        Assert.Equal(enabled.Text("publicKeyFingerprint"), status.Text("publicKeyFingerprint"));
    }

    [Fact]
    public async Task Keeps_the_public_half_and_nothing_else()
    {
        var (host, token) = Doctor();
        using var owned = host;

        await owned.CreateClient().PostAsync(Api.SigningEnable, token: token);

        var stored = owned.Read(db => db.SigningKeys.Single());

        // 0x04 then X then Y. A private key is 32 bytes and would fit nowhere
        // in this row -- which is the property the whole exercise is about.
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
        Assert.Equal(first.Text("keyLabel"), second.Text("keyLabel"));
        Assert.Equal(first.Text("publicKeyFingerprint"), second.Text("publicKeyFingerprint"));

        // A second key would not be an error anywhere the user can see, and
        // every report signed by the first would become unverifiable.
        Assert.Equal(1, owned.Read(db => db.SigningKeys.Count()));
    }

    [Fact]
    public async Task Re_adopts_a_key_the_device_still_holds_after_the_database_forgot_it()
    {
        var (host, token) = Doctor();
        using var owned = host;
        var client = owned.CreateClient();

        var first = await client.PostAsync(Api.SigningEnable, token: token);

        // The schema change in this ticket is delivered by deleting the database
        // file, so this is not hypothetical: the device keeps its keys, and the
        // rows that pointed at them are gone.
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

        // The same key, not a new one -- so reports signed before the reset
        // still verify.
        Assert.Equal(first.Text("keyLabel"), again.Text("keyLabel"));
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

        // Both live in the same token as the application's JWT key, and the
        // communicator looks keys up by label alone.
        Assert.NotEqual(mine.Text("keyLabel"), theirs.Text("keyLabel"));
        Assert.NotEqual(mine.Text("publicKeyFingerprint"), theirs.Text("publicKeyFingerprint"));

        var jwtLabel = owned.Read(db => db.JwtSigningKeys.Single().Label);

        Assert.NotEqual(jwtLabel, mine.Text("keyLabel"));
        Assert.NotEqual(jwtLabel, theirs.Text("keyLabel"));
    }

    [Fact]
    public async Task Refuses_to_hand_a_doctor_the_label_the_application_signs_tokens_with()
    {
        using var host = new MedSignHost();

        // Hsm:KeyLabel is configurable, so "the prefix keeps them apart" is a
        // convention rather than a guarantee. Point it straight at the label
        // the first doctor would be given.
        host.Settings["Hsm:KeyLabel"] = DoctorKeyLabel.For(1);

        var doctor = host.Account("h.novak", Roles.Doctor, "Dr. Helena Novak");

        Assert.Equal(1, doctor.Id);

        var answer = await host.CreateClient()
            .PostAsync(Api.SigningEnable, token: host.TokenFor(doctor));

        // Signing anything at all with the key MedSign issues sessions with
        // would let a doctor mint themselves a token. Refuse rather than share.
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

        // The same 503 the JWT path already produces when the Connector is down.
        // A 500 here would read as a bug in MedSign rather than an unplugged cable.
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

        // A failed enrolment that left the account looking enabled would fail
        // again, later, at the point where a report is being signed.
        Assert.False(status.Field("enabled")?.GetBoolean());
    }
}

/// <summary>
/// The stand-in for the hardware. It is only worth having if it is wrong in the
/// same ways the device would be -- so it makes genuine P-256 keys and signs
/// with them, and later verification tests exercise the real curve arithmetic
/// rather than agreeing with a stub.
/// </summary>
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

        // The device does not enforce unique labels; the lookup does. Without
        // this, "re-adopt rather than regenerate" would be untestable, because
        // a regenerating implementation would look identical from outside.
        Assert.Throws<HsmUnavailableException>(() => signer.FindKey("medsign-doctor-1"));
    }
}
