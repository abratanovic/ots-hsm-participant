using MedSign.Api.Shared;
using Microsoft.Extensions.Options;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace MedSign.Api.Hsm.Device;

public sealed class HsmCommunicator : IDisposable
{
    private readonly HsmOptions _options;
    private readonly ILogger<HsmCommunicator> _log;
    private readonly Pkcs11InteropFactories _factories = new();
    private readonly Lock _gate = new();

    private IPkcs11Library? _library;
    private bool _disposed;

    public HsmCommunicator(IOptions<HsmOptions> options, ILogger<HsmCommunicator> log)
    {
        _options = options.Value;
        _log = log;

        if (_options.ConfPath is { Length: > 0 } conf)
        {
            Environment.SetEnvironmentVariable("YUBIHSM_PKCS11_CONF", conf);
        }
    }

    public byte[] CreateKey(string label) => Execute(session =>
    {
        List<IObjectAttribute> publicTemplate =
        [
            Attribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            Attribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
            Attribute(CKA.CKA_LABEL, label),
            Attribute(CKA.CKA_TOKEN, true),
            Attribute(CKA.CKA_VERIFY, true),
            Attribute(CKA.CKA_EC_PARAMS, Pkcs11Constants.Secp256r1),
        ];

        List<IObjectAttribute> privateTemplate =
        [
            Attribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            Attribute(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
            Attribute(CKA.CKA_LABEL, label),
            Attribute(CKA.CKA_TOKEN, true),
            Attribute(CKA.CKA_PRIVATE, true),
            Attribute(CKA.CKA_SIGN, true),
            Attribute(CKA.CKA_SENSITIVE, true),
            Attribute(CKA.CKA_EXTRACTABLE, false),
        ];

        session.GenerateKeyPair(
            _factories.MechanismFactory.Create(CKM.CKM_EC_KEY_PAIR_GEN),
            publicTemplate,
            privateTemplate,
            out var publicKey,
            out _);

        _log.LogInformation("Generated a P-256 key pair on the HSM under label {Label}.", label);

        return ReadPoint(session, publicKey);
    });

    public byte[]? GetKey(string label) => Execute(session =>
    {
        var publicKey = FindOne(session, label, CKO.CKO_PUBLIC_KEY);

        return publicKey is null ? null : ReadPoint(session, publicKey);
    });

    public byte[] SignDigest(string label, byte[] digest) => Execute(session =>
    {
        var privateKey = FindOne(session, label, CKO.CKO_PRIVATE_KEY)
            ?? throw new HsmUnavailableException(
                $"The HSM is not holding a private key labelled {label}. Something recorded that key as "
                + "provisioned, so it was there once. Restarting the backend will provision a new one -- "
                + "and every token signed by the old key stops verifying the moment it does.");

        return session.Sign(_factories.MechanismFactory.Create(CKM.CKM_ECDSA), privateKey, digest);
    });

    private IObjectHandle? FindOne(ISession session, string label, CKO objectClass)
    {
        var found = session.FindAllObjects(
        [
            Attribute(CKA.CKA_CLASS, objectClass),
            Attribute(CKA.CKA_LABEL, label),
        ]);

        if (found.Count > 1)
        {
            throw new HsmUnavailableException(
                $"The HSM holds {found.Count} objects of class {objectClass} labelled {label}. MedSign "
                + "looks its key up by label, so a label has to identify exactly one object. Delete the "
                + "duplicates with yubihsm-shell and restart.");
        }

        return found.Count == 1 ? found[0] : null;
    }

    private static byte[] ReadPoint(ISession session, IObjectHandle publicKey)
    {
        var attribute = session.GetAttributeValue(publicKey, [CKA.CKA_EC_POINT]).Single();
        var point = EcPoint.Unwrap(attribute.GetValueAsByteArray());

        EcPoint.EnsureUncompressedP256(point);

        return point;
    }

    private IObjectAttribute Attribute(CKA type, object value) => value switch
    {
        string text => _factories.ObjectAttributeFactory.Create(type, text),
        bool flag => _factories.ObjectAttributeFactory.Create(type, flag),
        byte[] bytes => _factories.ObjectAttributeFactory.Create(type, bytes),
        CKO objectClass => _factories.ObjectAttributeFactory.Create(type, objectClass),
        CKK keyType => _factories.ObjectAttributeFactory.Create(type, keyType),
        _ => throw new ArgumentOutOfRangeException(nameof(value), value, "No attribute shape for this."),
    };

    private T Execute<T>(Func<ISession, T> work)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var session = OpenSession();

        try
        {
            return work(session);
        }
        finally
        {
            Close(session);
        }
    }

    private ISession OpenSession()
    {
        var pin = _options.ResolvePin();
        if (pin is not { Length: > 0 })
        {
            throw new HsmUnavailableException(
                "No PIN. Set MEDSIGN_HSM_PIN to your Authentication Key id as 4 lowercase hex digits "
                + "followed by your password, e.g. 1001<password>. There is no factory key to fall back on.");
        }

        var slot = Library().GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault()
            ?? throw new HsmUnavailableException(
                "No slot with a token present. Is the Connector running and reachable at the address "
                + "in yubihsm_pkcs11.conf?");

        var session = slot.OpenSession(SessionType.ReadWrite);

        try
        {
            session.Login(CKU.CKU_USER, pin);
        }
        catch (Pkcs11Exception ex)
        {
            session.Dispose();
            throw new HsmUnavailableException(LoginAdvice(ex), ex);
        }

        return session;
    }

    private static void Close(ISession session)
    {
        try
        {
            session.Logout();
        }
        catch (Pkcs11Exception)
        {
            // The session is being closed either way; a failed logout says it was already gone.
        }

        session.Dispose();
    }

    private IPkcs11Library Library()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_library is not null)
            {
                return _library;
            }

            if (_options.ModulePath is not { Length: > 0 })
            {
                throw new HsmUnavailableException("Hsm:ModulePath is not configured.");
            }

            if (!File.Exists(_options.ModulePath))
            {
                throw new HsmUnavailableException($"PKCS#11 module not found at {_options.ModulePath}.");
            }

            _library = _factories.Pkcs11LibraryFactory.LoadPkcs11Library(
                _factories, _options.ModulePath, AppType.MultiThreaded);

            _log.LogInformation("Loaded the PKCS#11 module at {Module}.", _options.ModulePath);

            return _library;
        }
    }

    private static string LoginAdvice(Pkcs11Exception ex) => ex.RV switch
    {
        CKR.CKR_PIN_INCORRECT =>
            "C_Login returned CKR_PIN_INCORRECT. The PIN is your Authentication Key id as 4 lowercase "
            + "hex digits followed by the password, e.g. 1001<password> -- the id prefix is easy to omit.",
        CKR.CKR_SESSION_COUNT =>
            "C_Login returned CKR_SESSION_COUNT: the device is holding all 16 sessions. Wait a few "
            + "seconds and try again -- idle sessions are reclaimed after 30 seconds.",
        _ => $"C_Login failed with {ex.RV}.",
    };

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _library?.Dispose();
            _library = null;
            _disposed = true;
        }
    }
}
