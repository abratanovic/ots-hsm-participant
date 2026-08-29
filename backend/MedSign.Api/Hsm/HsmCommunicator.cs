using MedSign.Api.Shared;
using Microsoft.Extensions.Options;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace MedSign.Api.Hsm;

/// <summary>
/// Everything MedSign asks of the HSM, and everything it takes to ask.
///
/// The lower half is the part every PKCS#11 integration needs and no tutorial
/// shows you: loading the module, finding a slot with a token in it, logging in
/// with a PIN that is not shaped like a PIN, and surviving a session the device
/// has quietly closed underneath you.
///
/// The upper half is the three operations this application actually performs.
/// They are deliberately few. A key is created, a key is looked up by label, and
/// a digest is signed -- MedSign never asks for the private key, because refusing
/// to hand it over is the one thing an HSM exists to do.
/// </summary>
public sealed class HsmCommunicator : IDisposable
{
    private readonly HsmOptions _options;
    private readonly ILogger<HsmCommunicator> _log;
    private readonly Pkcs11InteropFactories _factories = new();
    private readonly Lock _gate = new();

    private IPkcs11Library? _library;
    private ISession? _session;
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

    // ---- Operations ------------------------------------------------------

    /// <summary>
    /// Generates a P-256 key pair on the device under the given label and returns
    /// the public point, uncompressed.
    ///
    /// CKA_TOKEN keeps the key after the session ends, CKA_SIGN is what it may be
    /// used for, and CKA_EXTRACTABLE = false is the whole point of the exercise: the
    /// private half has no way out of the device, so there is no file to leak, no
    /// variable to print, and no copy to lose.
    /// </summary>
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

    /// <summary>
    /// The public point of the key stored under the given label, or null if the
    /// device is not holding one. Never the private half -- see CreateKey.
    /// </summary>
    public byte[]? GetKey(string label) => Execute(session =>
    {
        var publicKey = FindOne(session, label, CKO.CKO_PUBLIC_KEY);

        return publicKey is null ? null : ReadPoint(session, publicKey);
    });

    /// <summary>
    /// Signs a digest with the private key stored under the given label, and returns
    /// the raw R||S pair that a JWS signature -- or a PDF one -- is built from.
    ///
    /// CKM_ECDSA signs a digest that is already computed, so the device never sees
    /// the message. The key is looked up on every call rather than cached: an object
    /// handle does not survive the session being reset underneath us, and a label does.
    /// </summary>
    public byte[] SignDigest(string label, byte[] digest) => Execute(session =>
    {
        var privateKey = FindOne(session, label, CKO.CKO_PRIVATE_KEY)
            ?? throw new HsmUnavailableException(
                $"The HSM is not holding a private key labelled {label}. Something recorded that key as "
                + "provisioned, so it was there once. Restarting the backend will provision a new one -- "
                + "and every token signed by the old key stops verifying the moment it does.");

        return session.Sign(_factories.MechanismFactory.Create(CKM.CKM_ECDSA), privateKey, digest);
    });

    // ---- Objects ---------------------------------------------------------

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

    /// <summary>
    /// CKA_EC_POINT comes back as a DER OCTET STRING wrapping the point, and how
    /// much wrapping depends on the device. EcPoint.Unwrap takes it back off.
    /// </summary>
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

    // ---- Session ---------------------------------------------------------

    /// <summary>
    /// Runs the work against a logged-in session, and once more against a fresh one
    /// if the device had closed the first. Serialised: a PKCS#11 session is a single
    /// conversation, and two requests interleaved on it is not one.
    /// </summary>
    private T Execute<T>(Func<ISession, T> work)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            try
            {
                return work(Connect());
            }
            catch (Pkcs11Exception ex) when (IsRecoverable(ex))
            {
                _log.LogWarning("HSM session was not usable ({Rv}); reconnecting and retrying once.", ex.RV);
                Reset();
                return work(Connect());
            }
        }
    }

    private ISession Connect()
    {
        if (_session is not null)
        {
            return _session;
        }

        if (_options.ModulePath is not { Length: > 0 })
        {
            throw new HsmUnavailableException("Hsm:ModulePath is not configured.");
        }

        if (!File.Exists(_options.ModulePath))
        {
            throw new HsmUnavailableException($"PKCS#11 module not found at {_options.ModulePath}.");
        }

        var pin = _options.ResolvePin();
        if (pin is not { Length: > 0 })
        {
            throw new HsmUnavailableException(
                "No PIN. Set MEDSIGN_HSM_PIN to your Authentication Key id as 4 lowercase hex digits "
                + "followed by your password, e.g. 1001<password>. There is no factory key to fall back on.");
        }

        _library ??= _factories.Pkcs11LibraryFactory.LoadPkcs11Library(
            _factories, _options.ModulePath, AppType.MultiThreaded);

        var slot = _library.GetSlotList(SlotsType.WithTokenPresent).FirstOrDefault()
            ?? throw new HsmUnavailableException(
                "No slot with a token present. Is the Connector running and reachable at the address "
                + "in yubihsm_pkcs11.conf?");

        // Read-write, because provisioning generates a key pair on the device.
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

        var token = slot.GetTokenInfo();
        _log.LogInformation("HSM session open on {Token} (serial {Serial}).",
            token.Label.Trim(), token.SerialNumber.Trim());

        _session = session;
        return session;
    }

    private void Reset()
    {
        try
        {
            _session?.Logout();
        }
        catch (Pkcs11Exception)
        {
        }

        _session?.Dispose();
        _session = null;
    }

    private static bool IsRecoverable(Pkcs11Exception ex) => ex.RV is
        CKR.CKR_SESSION_HANDLE_INVALID or
        CKR.CKR_SESSION_CLOSED or
        CKR.CKR_USER_NOT_LOGGED_IN or
        CKR.CKR_DEVICE_ERROR;

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

            Reset();
            _library?.Dispose();
            _library = null;
            _disposed = true;
        }
    }
}
