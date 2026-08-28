using Microsoft.Extensions.Options;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace MedSign.Api.Hsm;

public sealed class HsmSessionHost : IDisposable
{
    private readonly HsmOptions _options;
    private readonly ILogger<HsmSessionHost> _log;
    private readonly Pkcs11InteropFactories _factories = new();
    private readonly Lock _gate = new();

    private IPkcs11Library? _library;
    private ISession? _session;
    private bool _disposed;

    public HsmSessionHost(IOptions<HsmOptions> options, ILogger<HsmSessionHost> log)
    {
        _options = options.Value;
        _log = log;

        if (_options.ConfPath is { Length: > 0 } conf)
        {
            Environment.SetEnvironmentVariable("YUBIHSM_PKCS11_CONF", conf);
        }
    }

    public T Execute<T>(Func<HsmContext, T> work)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            try
            {
                return work(new HsmContext(Connect, _factories));
            }
            catch (Pkcs11Exception ex) when (IsRecoverable(ex))
            {
                _log.LogWarning("HSM session was not usable ({Rv}); reconnecting and retrying once.", ex.RV);
                Reset();
                return work(new HsmContext(Connect, _factories));
            }
        }
    }

    public void Execute(Action<HsmContext> work) => Execute<object?>(hsm => { work(hsm); return null; });

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
