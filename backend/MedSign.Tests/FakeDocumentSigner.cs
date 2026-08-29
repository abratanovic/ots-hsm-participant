using System.Collections.Concurrent;
using System.Security.Cryptography;
using MedSign.Api.Hsm;

namespace MedSign.Tests;

/// <summary>
/// The YubiHSM, in software.
///
/// It holds P-256 keys by label and signs with them for real, so a test that
/// says "this report verifies" has been through the same curve arithmetic and
/// the same R||S encoding the device would produce. Canned signature bytes
/// would let a genuine bug in digest handling or signature encoding through --
/// this is the same trick <see cref="VirtualAuthenticator"/> plays for WebAuthn.
///
/// What it deliberately does not model is custody: these private keys are
/// ordinary .NET objects in this process. That property is the one thing only
/// the hardware has, and no test can assert it.
/// </summary>
public sealed class FakeDocumentSigner : IDocumentSigner, IDisposable
{
    /// <summary>
    /// Keys by label, plural on purpose. A label is not a primary key on the
    /// device: generating twice under one leaves two objects behind, and the
    /// failure shows up on the next lookup rather than at the second create.
    /// Modelling that is what makes "re-adopt, do not regenerate" testable --
    /// a fake that quietly returned the first key would pass either way.
    /// </summary>
    private readonly ConcurrentDictionary<string, List<ECDsa>> _keys = new(StringComparer.Ordinal);

    /// <summary>
    /// Unplugs it. Every operation then fails the way a missing Connector does,
    /// which is how the tests reach the device-unavailable path.
    /// </summary>
    public bool Unavailable { get; set; }

    public byte[]? FindKey(string label)
    {
        EnsureReachable();

        return FindOne(label) is { } key ? Point(key) : null;
    }

    public byte[] CreateKey(string label)
    {
        EnsureReachable();

        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        _keys.AddOrUpdate(label, _ => [key], (_, held) => [.. held, key]);

        return Point(key);
    }

    public byte[] SignDigest(string label, byte[] digest)
    {
        EnsureReachable();

        var key = FindOne(label)
            ?? throw new HsmUnavailableException($"No key labelled {label} on this device.");

        // Raw R||S, not DER -- what the device returns and what the verifier expects.
        return key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    /// <summary>Mirrors the communicator: a label has to name exactly one object.</summary>
    private ECDsa? FindOne(string label)
    {
        if (!_keys.TryGetValue(label, out var held))
        {
            return null;
        }

        if (held.Count > 1)
        {
            throw new HsmUnavailableException(
                $"The HSM holds {held.Count} keys labelled {label}. MedSign looks its key up by "
                + "label, so a label has to identify exactly one object.");
        }

        return held[0];
    }

    private void EnsureReachable()
    {
        if (Unavailable)
        {
            throw new HsmUnavailableException("The HSM is not reachable (the test unplugged it).");
        }
    }

    private static byte[] Point(ECDsa key)
    {
        var parameters = key.ExportParameters(includePrivateParameters: false);

        return [0x04, .. parameters.Q.X!, .. parameters.Q.Y!];
    }

    public void Dispose()
    {
        foreach (var key in _keys.Values.SelectMany(held => held))
        {
            key.Dispose();
        }

        _keys.Clear();
    }
}
