namespace MedSign.Api.Cloud.Kms;

public sealed class KmsOptions
{
    /// <summary>The AWS region holding the keys, for example <c>eu-west-1</c>.</summary>
    public string Region { get; init; } = "eu-west-1";

    /// <summary>
    /// One key for every label, given as a key id or ARN.
    ///
    /// A YubiHSM addresses keys by label, and MedSign has two kinds: the server's
    /// JWT key and one per doctor. KMS has no equivalent, so labels normally
    /// become aliases. Setting this instead points every label at a single
    /// pre-created key, which is what a demonstration wants: no keys are created,
    /// nothing is billed per participant, and the account needs one key that
    /// already exists.
    ///
    /// The trade-off is real and worth saying out loud: with one key, two
    /// doctors' reports carry the same signature key, so the fingerprint no
    /// longer identifies who signed. Leave it empty for the alias-per-label
    /// behaviour a deployment would actually use.
    /// </summary>
    public string KeyId { get; init; } = string.Empty;

    /// <summary>
    /// Whether a missing key may be created on the spot.
    ///
    /// Off by default, and deliberately so. Every doctor enabling signing would
    /// otherwise mint a real KMS key: billed monthly, outside the free tier, and
    /// impossible to delete on the day -- scheduled deletion waits days.
    /// </summary>
    public bool AllowKeyCreation { get; init; }

    public bool UsesSingleKey => !string.IsNullOrWhiteSpace(KeyId);

    /// <summary>What to call the key holding this label.</summary>
    public string Address(string label) => UsesSingleKey ? KeyId : $"alias/{label}";
}
