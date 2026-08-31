namespace MedSign.Api.Shared;

/// <summary>The values Signing:Provider accepts. See MedSignServices.AddSigning.</summary>
public static class SigningProviders
{
    /// <summary>JWT key from MEDSIGN_JWT_SIGNING_KEY, reports on the YubiHSM.</summary>
    public const string Env = "env";

    /// <summary>Both keys on the YubiHSM.</summary>
    public const string Hsm = "hsm";

    /// <summary>Both keys in AWS KMS.</summary>
    public const string Kms = "kms";
}
