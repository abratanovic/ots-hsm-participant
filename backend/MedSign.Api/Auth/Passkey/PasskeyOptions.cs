namespace MedSign.Api.Auth.Passkey;

public sealed class PasskeyOptions
{
    public string RpId { get; init; } = "localhost";

    public string RpName { get; init; } = "MedSign Cloud";

    public IReadOnlyList<string> Origins { get; init; } =
    [
        "http://localhost:4200",
        "http://localhost:5000",
    ];

    public int TimeoutMs { get; init; } = 120_000;

    public TimeSpan ChallengeLifetime { get; init; } = TimeSpan.FromMinutes(5);
}
