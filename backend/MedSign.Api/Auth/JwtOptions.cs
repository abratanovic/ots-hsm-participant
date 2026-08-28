namespace MedSign.Api.Auth;

public sealed class JwtOptions
{
    public string Issuer { get; init; } = "https://medsign.example";
    public string Audience { get; init; } = "medsign-cloud";
    public int LifetimeMinutes { get; init; } = 60;
}
