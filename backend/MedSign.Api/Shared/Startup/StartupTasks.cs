using MedSign.Api.Hsm.Device;
using MedSign.Api.Hsm.Reports;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Shared.Startup;

public static class StartupTasks
{
    public static void RunStartupTasks(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var services = scope.ServiceProvider;

        var db = services.GetRequiredService<MedSignDb>();
        db.Database.EnsureCreated();

        services.GetRequiredService<ReportStorage>().EnsureDirectory();

        ProvisionSigningKey(services);
        StartupBanner.Print(app, services, db);
    }

    private static void ProvisionSigningKey(IServiceProvider services)
    {
        var store = services.GetRequiredService<IJwtSigningKeyStore>();
        var provider = services.GetRequiredService<IJwtSigningProvider>();
        var label = services.GetRequiredService<IOptions<HsmOptions>>().Value.KeyLabel;
        var log = services.GetRequiredService<ILogger<Program>>();

        var stored = store.Current();

        try
        {
            var key = provider.ProvisionSigningKey(label);

            EnsureUsable(key, label);

            if (stored is null)
            {
                store.Register(key);

                log.LogInformation("JWT Signing Key provisioned on {Provider}: label={Label} kid={Kid}",
                    provider.Name, key.Label, key.Kid);

                return;
            }

            if (stored.Kid == key.Kid)
            {
                return;
            }

            store.Replace(key);

            log.LogWarning("The JWT Signing Key on {Provider} is not the one MedSign Cloud had recorded "
                + "(kid {StoredKid} -> {CurrentKid}). The key the provider actually holds wins: tokens "
                + "and the JWKS now both follow it.",
                provider.Name, stored.Kid, key.Kid);
        }
        catch (Exception failure)
        {
            if (stored is not null)
            {
                log.LogWarning("Could not re-read the JWT Signing Key from {Provider}: {Message} "
                    + "Keeping the recorded key (kid {Kid}).",
                    provider.Name, failure.Message, stored.Kid);

                return;
            }

            services.GetRequiredService<SigningKeyStatus>().RecordFailure(failure);

            log.LogWarning("No JWT Signing Key on {Provider}: {Message} "
                + "MedSign Cloud will start, and say so on the first sign-in.",
                provider.Name, failure.Message);
        }
    }

    private static void EnsureUsable(JwtSigningKey key, string expectedLabel)
    {
        if (key.Label != expectedLabel)
        {
            throw new InvalidOperationException(
                $"The key was registered under label '{key.Label}' but the configured label is "
                + $"'{expectedLabel}'. SignDigest looks the key up by label, so the two have to match.");
        }

        if (string.IsNullOrWhiteSpace(key.Kid))
        {
            throw new InvalidOperationException(
                "The key has no kid. Every token header names one, and the JWKS is keyed on it. "
                + "Derive it from the public point: Base64Url.Encode(SHA256.HashData(point)).");
        }

        EcPoint.EnsureUncompressedP256(key.EcPoint);
    }
}
