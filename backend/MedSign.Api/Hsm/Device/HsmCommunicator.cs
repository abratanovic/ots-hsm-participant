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

        // The YubiHSM PKCS#11 module reads its connector address out of a file
        // named by this variable, not out of anything you pass to it in code.
        if (_options.ConfPath is { Length: > 0 } conf)
        {
            Environment.SetEnvironmentVariable("YUBIHSM_PKCS11_CONF", conf);
        }
    }

    public byte[] CreateKey(string label)
    {
        // TODO HSM 2/8: Generate a P-256 (secp256r1) key pair on the device and
        // return the public point.
        //
        // Run the work through Execute(session => ...) so you are handed a live
        // session. Build two attribute templates with the Attribute() helper
        // below -- one for the public key, one for the private key:
        //
        //   both     CKA_CLASS (CKO_PUBLIC_KEY / CKO_PRIVATE_KEY),
        //            CKA_KEY_TYPE = CKK_EC, CKA_LABEL = label, CKA_TOKEN = true
        //            (CKA_TOKEN false would give you a key that dies with the
        //            session)
        //   public   CKA_VERIFY = true, CKA_EC_PARAMS = Pkcs11Constants.Secp256r1
        //            (the DER OID of the curve -- this is how you pick P-256)
        //   private  CKA_PRIVATE = true, CKA_SIGN = true, CKA_SENSITIVE = true,
        //            CKA_EXTRACTABLE = false -- the two flags that make the
        //            private half unreadable, forever, even by you
        //
        // Then session.GenerateKeyPair() with a CKM_EC_KEY_PAIR_GEN mechanism
        // from _factories.MechanismFactory, and hand the public key handle it
        // gives you to ReadPoint(). Log what you generated; a key appearing on
        // the device unannounced is hard to explain later.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Device/HsmCommunicator.cs#L42-L76
        throw new NotImplementedException(
            "Exercise HSM 5/10: generate the key pair in HsmCommunicator.CreateKey.");
    }

    public byte[]? GetKey(string label)
    {
        // TODO HSM 5/8: Return the public point of the public key stored under
        // this label, or null when the device is not holding one.
        //
        // Run it through Execute(), find the CKO_PUBLIC_KEY with FindOne(), and
        // read it with ReadPoint(). The null matters: HsmJwtSigningProvider does
        // GetKey(label) ?? CreateKey(label), so a null that should have been a
        // handle silently provisions a second key -- and every token signed by
        // the first one stops verifying.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Device/HsmCommunicator.cs#L78-L83
        throw new NotImplementedException(
            "Exercise HSM 4/10: look the public key up in HsmCommunicator.GetKey.");
    }

    public byte[] SignDigest(string label, byte[] digest)
    {
        // TODO HSM 6/8: Sign an already-hashed 32-byte digest with the private
        // key stored under this label.
        //
        // Run it through Execute(), find the CKO_PRIVATE_KEY with FindOne(), and
        // call session.Sign() with a CKM_ECDSA mechanism from
        // _factories.MechanismFactory. Note what CKM_ECDSA means: the device
        // signs the digest exactly as given and does not hash it for you, and
        // what comes back is the raw r||s pair (64 bytes), not a DER SEQUENCE --
        // which is precisely the shape JWS and MedSign's verifier want.
        //
        // A missing private key is not a null case here. Something already
        // recorded this key as provisioned, so throw HsmUnavailableException and
        // say so; restarting will provision a new key and invalidate every token
        // the old one signed.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Device/HsmCommunicator.cs#L85-L94
        throw new NotImplementedException(
            "Exercise HSM 6/10: sign the digest in HsmCommunicator.SignDigest.");
    }

    private IObjectHandle? FindOne(ISession session, string label, CKO objectClass)
    {
        // TODO HSM 3/8: Return the one object of this class carrying this label,
        // or null when there is none.
        //
        // PKCS#11 has no lookup-by-name. You search by attribute template:
        // session.FindAllObjects() with CKA_CLASS and CKA_LABEL, built with the
        // Attribute() helper below, and you get back a list of handles. A handle
        // is a session-scoped integer, not the key.
        //
        // Handle all three counts. Zero is null -- that is how GetKey answers
        // "not provisioned yet". One is your answer. More than one is not
        // recoverable by guessing: MedSign addresses its key by label, so throw
        // HsmUnavailableException and tell the reader to delete the duplicates
        // with yubihsm-shell.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Device/HsmCommunicator.cs#L96-L113
        throw new NotImplementedException(
            "Exercise HSM 2/10: search the device by template in HsmCommunicator.FindOne.");
    }

    private static byte[] ReadPoint(ISession session, IObjectHandle publicKey)
    {
        // TODO HSM 4/8: Read CKA_EC_POINT off this public key handle and return
        // it as a 65-byte uncompressed P-256 point (0x04 || X || Y).
        //
        // session.GetAttributeValue(handle, [CKA.CKA_EC_POINT]) gives you a list
        // of attributes; take the single one and call GetValueAsByteArray().
        //
        // What you get is not yet the point. PKCS#11 specifies CKA_EC_POINT as a
        // DER OCTET STRING wrapping the point, and modules disagree about
        // whether they hand you the wrapper -- EcPoint.Unwrap() in Shared/ copes
        // with both, so run the bytes through it. Then call
        // EcPoint.EnsureUncompressedP256() so a wrong shape fails here, at the
        // device boundary, instead of much later as an unverifiable signature.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Device/HsmCommunicator.cs#L115-L123
        throw new NotImplementedException(
            "Exercise HSM 3/10: read the public point in HsmCommunicator.ReadPoint.");
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
        // TODO HSM 1/8: Return a session that is open and logged in, freshly,
        // for one operation. Start here -- nothing else in this class runs until
        // it works. Close() below is the other half of the exercise.
        //
        // Every call gets its own session: MedSign signs for many participants
        // at once, and a session cached in a field would have to be serialised
        // behind a lock. The device allows 16 at a time, which is what makes
        // closing them promptly -- Close(), in Execute's finally -- the price of
        // opening them freely.
        //
        // In order:
        //
        //   1. Refuse to continue without a PIN from _options.ResolvePin().
        //      Throw HsmUnavailableException saying so -- the PIN is your
        //      Authentication Key id as 4 lowercase hex digits followed by the
        //      password, e.g. 1001<password>, and there is no default.
        //   2. Library().GetSlotList(SlotsType.WithTokenPresent) and take the
        //      first. An empty list means the Connector is not running or is not
        //      at the address in yubihsm_pkcs11.conf; say that.
        //   3. slot.OpenSession(SessionType.ReadWrite) -- a read-only session
        //      cannot generate keys.
        //   4. session.Login(CKU.CKU_USER, pin). Dispose the session and rethrow
        //      as HsmUnavailableException(LoginAdvice(ex), ex) when it fails; a
        //      session left open on a failed login is one of the 16 you cannot
        //      get back.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Hsm/Device/HsmCommunicator.cs#L151-L179
        throw new NotImplementedException(
            "Exercise HSM 1/10: open and log in to the session in HsmCommunicator.OpenSession.");
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
