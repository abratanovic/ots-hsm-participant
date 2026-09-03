using MedSign.Api.Hsm.Device;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace MedSign.Tests;

[Collection(HsmExerciseCollection.Name)]
public sealed class ExerciseNineOpenSessionTests
{
    [Fact]
    public void Operation_uses_an_authenticated_read_write_session_and_always_closes_it()
    {
        var hsm = HsmRig.Create();

        Exercise.OrSkip(() => hsm.Subject.GetKey("missing"));

        hsm.Library.Verify(x => x.GetSlotList(SlotsType.WithTokenPresent), Times.Once);
        hsm.Slot.Verify(x => x.OpenSession(SessionType.ReadWrite), Times.Once);
        hsm.Session.Verify(x => x.Login(CKU.CKU_USER, "1001workshop"), Times.Once);
        hsm.Session.Verify(x => x.Logout(), Times.Once);
        hsm.Session.Verify(x => x.Dispose(), Times.Once);
    }

    [Fact]
    public void Missing_pin_stops_before_the_device_is_contacted()
    {
        var hsm = HsmRig.Create(pin: null);

        var error = Exercise.ThrowsOrSkip<HsmUnavailableException>(() => hsm.Subject.GetKey("key"));

        Assert.Contains("PIN", error.Message);
        hsm.Library.Verify(x => x.GetSlotList(It.IsAny<SlotsType>()), Times.Never);
    }

    [Fact]
    public void Failed_login_disposes_the_open_session()
    {
        var hsm = HsmRig.Create();
        hsm.Session.Setup(x => x.Login(CKU.CKU_USER, It.IsAny<string>()))
            .Throws(new Pkcs11Exception("C_Login", CKR.CKR_PIN_INCORRECT));

        var error = Exercise.ThrowsOrSkip<HsmUnavailableException>(() => hsm.Subject.GetKey("key"));

        Assert.Contains("CKR_PIN_INCORRECT", error.Message);
        hsm.Session.Verify(x => x.Dispose(), Times.Once);
        hsm.Session.Verify(x => x.FindAllObjects(It.IsAny<List<IObjectAttribute>>()), Times.Never);
    }
}

[Collection(HsmExerciseCollection.Name)]
public sealed class ExerciseNineFindOneTests
{
    [Fact]
    public void Search_uses_both_the_label_and_requested_object_class()
    {
        var hsm = HsmRig.Create();
        List<IObjectAttribute>? search = null;
        hsm.Session.Setup(x => x.FindAllObjects(It.IsAny<List<IObjectAttribute>>()))
            .Callback<List<IObjectAttribute>>(value => search = value)
            .Returns([]);

        Exercise.OrSkip(() => hsm.Subject.GetKey("doctor-7"));

        Assert.NotNull(search);
        Assert.Equal("doctor-7", HsmRig.Attribute(search!, CKA.CKA_LABEL).GetValueAsString());
        Assert.Equal((ulong)CKO.CKO_PUBLIC_KEY, HsmRig.Attribute(search!, CKA.CKA_CLASS).GetValueAsUlong());
    }

    [Fact]
    public void Ambiguous_label_is_refused_before_an_object_is_used()
    {
        var hsm = HsmRig.Create();
        hsm.Session.Setup(x => x.FindAllObjects(It.IsAny<List<IObjectAttribute>>()))
            .Returns([Mock.Of<IObjectHandle>(), Mock.Of<IObjectHandle>()]);

        var error = Exercise.ThrowsOrSkip<HsmUnavailableException>(() => hsm.Subject.GetKey("duplicate"));

        Assert.Contains("2 objects", error.Message);
        hsm.Session.Verify(
            x => x.GetAttributeValue(It.IsAny<IObjectHandle>(), It.IsAny<List<CKA>>()), Times.Never);
    }
}

[Collection(HsmExerciseCollection.Name)]
public sealed class ExerciseNineGetKeyTests
{
    [Fact]
    public void Missing_public_key_returns_null()
    {
        var hsm = HsmRig.Create();

        Assert.Null(Exercise.OrSkip(() => hsm.Subject.GetKey("absent")));
    }

    [Fact]
    public void Existing_public_key_returns_its_point()
    {
        var hsm = HsmRig.Create();
        var handle = Mock.Of<IObjectHandle>();
        var point = HsmRig.Point();
        hsm.FindReturns(handle);
        hsm.PointReturns(handle, point);

        Assert.Equal(point, Exercise.OrSkip(() => hsm.Subject.GetKey("present")));
    }
}

[Collection(HsmExerciseCollection.Name)]
public sealed class ExerciseNineReadPointTests
{
    [Fact]
    public void Der_wrapped_point_is_unwrapped()
    {
        var hsm = HsmRig.Create();
        var handle = Mock.Of<IObjectHandle>();
        var point = HsmRig.Point();
        var wrapped = new byte[] { 0x04, 0x41 }.Concat(point).ToArray();
        hsm.FindReturns(handle);
        hsm.PointReturns(handle, wrapped);

        Assert.Equal(point, Exercise.OrSkip(() => hsm.Subject.GetKey("wrapped")));
        hsm.Session.Verify(x => x.GetAttributeValue(
            handle, It.Is<List<CKA>>(a => a.Count == 1 && a[0] == CKA.CKA_EC_POINT)), Times.Once);
    }

    [Fact]
    public void Malformed_or_wrong_curve_point_is_rejected()
    {
        var hsm = HsmRig.Create();
        var handle = Mock.Of<IObjectHandle>();
        hsm.FindReturns(handle);
        hsm.PointReturns(handle, new byte[64]);

        Exercise.ThrowsOrSkip<InvalidOperationException>(() => hsm.Subject.GetKey("bad-point"));
    }
}

[Collection(HsmExerciseCollection.Name)]
public sealed class ExerciseNineSignDigestTests
{
    [Fact]
    public void Digest_is_signed_unchanged_with_the_private_key_and_raw_ecdsa()
    {
        var hsm = HsmRig.Create();
        var key = Mock.Of<IObjectHandle>();
        var digest = Enumerable.Range(0, 32).Select(x => (byte)x).ToArray();
        var signature = Enumerable.Repeat((byte)0x5a, 64).ToArray();
        hsm.FindReturns(key);
        hsm.Session.Setup(x => x.Sign(
                It.Is<IMechanism>(m => m.Type == (ulong)CKM.CKM_ECDSA), key, digest))
            .Returns(signature);

        Assert.Same(signature, Exercise.OrSkip(() => hsm.Subject.SignDigest("jwt", digest)));
        hsm.AssertSearch("jwt", CKO.CKO_PRIVATE_KEY);
    }

    [Fact]
    public void Missing_private_key_fails_without_attempting_a_signature()
    {
        var hsm = HsmRig.Create();

        Exercise.ThrowsOrSkip<HsmUnavailableException>(
            () => hsm.Subject.SignDigest("gone", new byte[32]));
        hsm.Session.Verify(x => x.Sign(
            It.IsAny<IMechanism>(), It.IsAny<IObjectHandle>(), It.IsAny<byte[]>()), Times.Never);
    }
}

[Collection(HsmExerciseCollection.Name)]
public sealed class ExerciseNineCreateKeyTests
{
    [Fact]
    public void Creates_a_persistent_non_extractable_P256_signing_pair_and_returns_the_public_point()
    {
        var hsm = HsmRig.Create();
        var publicKey = Mock.Of<IObjectHandle>();
        var privateKey = Mock.Of<IObjectHandle>();
        var point = HsmRig.Point();
        List<IObjectAttribute>? publicTemplate = null;
        List<IObjectAttribute>? privateTemplate = null;

        hsm.Session.Setup(x => x.GenerateKeyPair(
                It.Is<IMechanism>(m => m.Type == (ulong)CKM.CKM_EC_KEY_PAIR_GEN),
                It.IsAny<List<IObjectAttribute>>(), It.IsAny<List<IObjectAttribute>>(),
                out publicKey, out privateKey))
            .Callback(new GeneratePairCallback((IMechanism _, List<IObjectAttribute> pub,
                List<IObjectAttribute> priv, out IObjectHandle returnedPublic, out IObjectHandle returnedPrivate) =>
            {
                publicTemplate = pub;
                privateTemplate = priv;
                returnedPublic = publicKey;
                returnedPrivate = privateKey;
            }));
        hsm.PointReturns(publicKey, point);

        Assert.Equal(point, Exercise.OrSkip(() => hsm.Subject.CreateKey("medsign-jwt")));

        AssertTemplate(publicTemplate!, "medsign-jwt", CKO.CKO_PUBLIC_KEY,
            (CKA.CKA_TOKEN, true), (CKA.CKA_VERIFY, true));
        Assert.Equal(Pkcs11Constants.Secp256r1,
            HsmRig.Attribute(publicTemplate!, CKA.CKA_EC_PARAMS).GetValueAsByteArray());
        AssertTemplate(privateTemplate!, "medsign-jwt", CKO.CKO_PRIVATE_KEY,
            (CKA.CKA_TOKEN, true), (CKA.CKA_PRIVATE, true), (CKA.CKA_SIGN, true),
            (CKA.CKA_SENSITIVE, true), (CKA.CKA_EXTRACTABLE, false));
    }

    private static void AssertTemplate(
        List<IObjectAttribute> attributes, string label, CKO objectClass, params (CKA Type, bool Value)[] flags)
    {
        Assert.Equal(label, HsmRig.Attribute(attributes, CKA.CKA_LABEL).GetValueAsString());
        Assert.Equal((ulong)objectClass, HsmRig.Attribute(attributes, CKA.CKA_CLASS).GetValueAsUlong());
        Assert.Equal((ulong)CKK.CKK_EC, HsmRig.Attribute(attributes, CKA.CKA_KEY_TYPE).GetValueAsUlong());
        foreach (var (type, value) in flags)
            Assert.Equal(value, HsmRig.Attribute(attributes, type).GetValueAsBool());
    }

    private delegate void GeneratePairCallback(
        IMechanism mechanism, List<IObjectAttribute> publicTemplate, List<IObjectAttribute> privateTemplate,
        out IObjectHandle publicKey, out IObjectHandle privateKey);
}

internal sealed class HsmRig
{
    public Mock<IPkcs11Library> Library { get; } = new(MockBehavior.Strict);
    public Mock<ISlot> Slot { get; } = new(MockBehavior.Strict);
    public Mock<ISession> Session { get; } = new(MockBehavior.Loose);
    public HsmCommunicator Subject { get; }

    private HsmRig(string? pin)
    {
        Library.Setup(x => x.GetSlotList(SlotsType.WithTokenPresent)).Returns([Slot.Object]);
        Slot.Setup(x => x.OpenSession(SessionType.ReadWrite)).Returns(Session.Object);
        Session.Setup(x => x.FindAllObjects(It.IsAny<List<IObjectAttribute>>())).Returns([]);

        Subject = new HsmCommunicator(
            Options.Create(new HsmOptions { Pin = pin ?? "" }),
            NullLogger<HsmCommunicator>.Instance,
            () => Library.Object,
            () => pin ?? "");
    }

    public static HsmRig Create(string? pin = "1001workshop") => new(pin);

    public void FindReturns(params IObjectHandle[] handles) =>
        Session.Setup(x => x.FindAllObjects(It.IsAny<List<IObjectAttribute>>())).Returns([.. handles]);

    public void PointReturns(IObjectHandle handle, byte[] bytes)
    {
        var attribute = new Mock<IObjectAttribute>();
        attribute.Setup(x => x.GetValueAsByteArray()).Returns(bytes);
        Session.Setup(x => x.GetAttributeValue(handle, It.IsAny<List<CKA>>())).Returns([attribute.Object]);
    }

    public void AssertSearch(string label, CKO objectClass) => Session.Verify(x => x.FindAllObjects(
        It.Is<List<IObjectAttribute>>(a =>
            Attribute(a, CKA.CKA_LABEL).GetValueAsString() == label &&
            Attribute(a, CKA.CKA_CLASS).GetValueAsUlong() == (ulong)objectClass)), Times.Once);

    public static IObjectAttribute Attribute(IEnumerable<IObjectAttribute> attributes, CKA type) =>
        Assert.Single(attributes, a => a.Type == (ulong)type);

    public static byte[] Point() => [0x04, .. Enumerable.Range(1, 64).Select(x => (byte)x)];
}

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class HsmExerciseCollection
{
    public const string Name = "HSM exercises";
}
