using System.Text.Json.Serialization;
using Fido2NetLib;
using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Data;
using MedSign.Api.Hsm;
using MedSign.Api.Lab;
using MedSign.Api.Signing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Startup;

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

        services.AddDbContext<MedSignDb>(options => options.UseSqlite(
            builder.Configuration.GetConnectionString("MedSign") ?? "Data Source=medsign.db"));

        services.AddScoped<IJwtSigningKeyStore, JwtSigningKeyStore>();
        services.AddScoped<Claims>();
        services.AddScoped<JwtIssuer>();
        services.AddScoped<SessionIssuer>();

        services.AddPasskeys();
        services.AddSigning();
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

        services.AddSingleton<SigningKeyStatus>();

        // Exercise 2 swaps this one line for HsmJwtSigningProvider.
        services.AddSingleton<IJwtSigningProvider, EnvJwtSigningProvider>();
    }

    private static void AddLoopbackCors(this IServiceCollection services) =>
        services.AddCors(options => options.AddDefaultPolicy(policy => policy
            .SetIsOriginAllowed(origin =>
                Uri.TryCreate(origin, UriKind.Absolute, out var uri) && uri.IsLoopback)
            .AllowAnyHeader()
            .AllowAnyMethod()));
}
