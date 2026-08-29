using System.Text.Json.Serialization;
using Fido2NetLib;
using MedSign.Api.Hsm;
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
        services.AddSigning();
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

    private static void AddSigning(this IServiceCollection services)
    {
        services.AddSingleton<HsmCommunicator>();

        // The seam the tests substitute: a YubiHSM has no simulator, so without
        // it nothing that signs a document could be tested at all.
        services.AddSingleton<IDocumentSigner, HsmDocumentSigner>();
        services.AddScoped<DoctorSigningKeys>();

        services.AddSingleton<SigningKeyStatus>();

        // Exercise 2 swaps this one line for HsmJwtSigningProvider.
        services.AddSingleton<IJwtSigningProvider, EnvJwtSigningProvider>();
    }

    private static void AddReports(this IServiceCollection services)
    {
        // QuestPDF refuses to render until it has been told which licence it is
        // being used under, and it throws when it finds out at the first
        // render rather than here. MedSign is open source and nowhere near the
        // revenue threshold, so the Community terms apply.
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
