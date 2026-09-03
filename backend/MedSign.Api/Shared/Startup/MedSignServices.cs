using System.Text.Json.Serialization;
using Fido2NetLib;
using MedSign.Api.Cloud.Kms;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Hsm.Reports;
using MedSign.Api.Passkeys;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using QuestPDF.Infrastructure;

namespace MedSign.Api.Shared.Startup;

public static class MedSignServices
{
    private const int ChallengeBytes = 32;

    public static void AddMedSignServices(this WebApplicationBuilder builder)
    {
        var services = builder.Services;

        services.AddOpenApi();
        services.AddSingleton(TimeProvider.System);

        services.ConfigureHttpJsonOptions(options =>
            options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull);

        services.Configure<HsmOptions>(builder.Configuration.GetSection("Hsm"));
        services.Configure<KmsOptions>(builder.Configuration.GetSection("Kms"));
        services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
        services.Configure<PasskeyOptions>(builder.Configuration.GetSection("Passkey"));
        services.Configure<ReportStorageOptions>(builder.Configuration.GetSection("Storage"));

        services.AddDbContext<MedSignDb>(options => options.UseSqlite(
            builder.Configuration.GetConnectionString("MedSign") ?? "Data Source=medsign.db"));

        services.AddScoped<IJwtSigningKeyStore, JwtSigningKeyStore>();
        services.AddScoped<Claims>();
        services.AddScoped<JwtIssuer>();
        services.AddScoped<SessionIssuer>();

        services.AddPasskeys();
        services.AddSigning(builder.Configuration);
        services.AddReports();
        services.AddLoopbackCors();
    }

    private static void AddPasskeys(this IServiceCollection services)
    {
        services.AddSingleton(provider =>
        {
            var passkey = provider.GetRequiredService<IOptions<PasskeyOptions>>().Value;

            return new Fido2Configuration
            {
                ServerDomain = passkey.RpId,
                ServerName = passkey.RpName,
                Origins = passkey.Origins.ToHashSet(StringComparer.Ordinal),
                Timeout = (uint)passkey.TimeoutMs,
                ChallengeSize = ChallengeBytes,
            };
        });

        services.AddScoped<IFido2>(provider =>
            new Fido2(provider.GetRequiredService<Fido2Configuration>()));

        services.AddSingleton<PasskeyChallengeStore>();
        services.AddScoped<MedSignPasskeys>();
    }

    /// <summary>
    /// Chooses what holds the signing keys.
    ///
    /// One setting moves both halves together -- the JWT the session rides on and
    /// the key a doctor signs reports with -- because a deployment where those
    /// two live in different places is a deployment nobody meant to build.
    ///
    /// Everything above this line is unaware of the choice. That is the claim the
    /// workshop makes about abstraction boundaries, and this method is where it
    /// is either true or a nice story.
    /// </summary>
    private static void AddSigning(this IServiceCollection services, IConfiguration configuration)
    {
        var provider = configuration["Signing:Provider"] ?? SigningProviders.Hsm;

        services.AddSingleton<HsmCommunicator>();
        services.AddSingleton<KmsCommunicator>();

        services.AddScoped<DoctorSigningKeys>();
        services.AddSingleton<SigningKeyStatus>();

        switch (provider.Trim().ToLowerInvariant())
        {
            case SigningProviders.Env:
                // The key in an environment variable anyone can read -- which is
                // the point exercise 1 makes, and why this is no longer the default.
                services.AddSingleton<IJwtSigningProvider, EnvJwtSigningProvider>();
                services.AddSingleton<IDocumentSigner, HsmDocumentSigner>();
                break;

            case SigningProviders.Hsm:
                // The default: both keys on the device.
                services.AddSingleton<IJwtSigningProvider, HsmJwtSigningProvider>();
                services.AddSingleton<IDocumentSigner, HsmDocumentSigner>();
                break;

            case SigningProviders.Kms:
                services.AddSingleton<IJwtSigningProvider, KmsJwtSigningProvider>();
                services.AddSingleton<IDocumentSigner, KmsDocumentSigner>();
                break;

            default:
                // Loudly, and at startup. A typo that quietly fell back to the
                // default would look like a working demonstration of the wrong
                // thing -- signatures made in the wrong place, and nobody the wiser.
                throw new InvalidOperationException(
                    $"Signing:Provider is '{provider}'. It has to be one of "
                    + $"'{SigningProviders.Env}', '{SigningProviders.Hsm}' or "
                    + $"'{SigningProviders.Kms}'.");
        }
    }

    private static void AddReports(this IServiceCollection services)
    {
        QuestPDF.Settings.License = LicenseType.Community;

        services.AddSingleton<ReportStorage>();
        services.AddScoped<ReportIssuing>();
        services.AddScoped<ReportAccess>();
        services.AddScoped<ReportVerification>();
    }

    private static void AddLoopbackCors(this IServiceCollection services) =>
        services.AddCors(options => options.AddDefaultPolicy(policy => policy
            .SetIsOriginAllowed(origin =>
                Uri.TryCreate(origin, UriKind.Absolute, out var uri) && uri.IsLoopback)
            .AllowAnyHeader()
            .AllowAnyMethod()));
}
