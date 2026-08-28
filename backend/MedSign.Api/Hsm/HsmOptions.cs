namespace MedSign.Api.Hsm;

public sealed class HsmOptions
{
    public string ModulePath { get; init; } = "";

    public string ConfPath { get; init; } = "";

    public string Pin { get; init; } = "";

    public string KeyLabel { get; init; } = "medsign-jwt-signing";

    public string ResolvePin() =>
        Environment.GetEnvironmentVariable("MEDSIGN_HSM_PIN") is { Length: > 0 } fromEnv ? fromEnv : Pin;
}
