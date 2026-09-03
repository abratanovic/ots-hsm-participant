using MedSign.Api.Shared;
using MedSign.Api.Cloud.Kms;
using MedSign.Api.Tokens;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Shared.Startup;

public static class StartupBanner
{
    public static void Print(WebApplication app, IServiceProvider services, MedSignDb db)
    {
        var provider = services.GetRequiredService<IJwtSigningProvider>();
        var key = services.GetRequiredService<IJwtSigningKeyStore>().Current();
        var passkey = app.Configuration.GetSection("Passkey");

        Console.WriteLine();
        Console.WriteLine("  MedSign Cloud -- Participant Backend");
        Console.WriteLine("  ------------------------------------");
        Console.WriteLine($"  Relying party  : {passkey["RpId"] ?? "localhost"}  (http://127.0.0.1 will NOT work)");
        Console.WriteLine($"  Accounts       : {db.Users.AsNoTracking().Count()} registered");
        Console.WriteLine($"  Signing        : {provider.Name}");

        switch (provider)
        {
            case EnvJwtSigningProvider:
                PrintLocalKey();
                break;

            case KmsJwtSigningProvider:
                PrintKms(app.Configuration.GetSection("Kms"));
                break;

            default:
                PrintHsm(app.Configuration.GetSection("Hsm"));
                break;
        }

        PrintSigningKey(key, services.GetRequiredService<SigningKeyStatus>());

        Console.WriteLine();
    }

    private static void PrintLocalKey()
    {
        Console.WriteLine($"  Key source     : {EnvJwtSigningProvider.KeyVariable} (environment)");
        Console.WriteLine("                   Anyone who can read that variable can mint a doctor token.");
    }

    private static void PrintKms(IConfiguration kms)
    {
        var credentials = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID"));
        var session = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN"));
        var keyId = kms["KeyId"];

        Console.WriteLine($"  Region         : {kms["Region"]}");
        Console.WriteLine($"  Key            : {(string.IsNullOrEmpty(keyId) ? "alias per label" : keyId)}");
        Console.WriteLine($"  Credentials    : {(credentials
            ? session ? "set (session token, so it expires)" : "set"
            : "NOT SET -- set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")}");
        Console.WriteLine("                   The YubiHSM is not in this picture at all.");
    }

    private static void PrintHsm(IConfiguration hsm)
    {
        var pinSet = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("MEDSIGN_HSM_PIN"))
                     || !string.IsNullOrEmpty(hsm["Pin"]);

        Console.WriteLine($"  PKCS#11 module : {hsm["ModulePath"]}");
        Console.WriteLine($"  PIN            : {(pinSet ? "set" : "NOT SET -- set MEDSIGN_HSM_PIN=<id><password>")}");
        Console.WriteLine($"  Key label      : {hsm["KeyLabel"]}");
    }

    private static void PrintSigningKey(JwtSigningKey? key, SigningKeyStatus status)
    {
        if (key is not null)
        {
            Console.WriteLine("  JWT signing    : ready");
            Console.WriteLine($"  kid            : {key.Kid}");
            return;
        }

        Console.WriteLine("  JWT signing    : NO KEY -- sign-in will fail until there is one");
        Console.WriteLine($"                   {status.ProvisioningFailure?.Message ?? "not provisioned"}");
    }
}
