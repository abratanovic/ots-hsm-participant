using System.Collections.Concurrent;
using System.Security.Cryptography;
using MedSign.Api.Hsm.Device;

namespace MedSign.Tests;

public sealed class FakeDocumentSigner : IDocumentSigner, IDisposable
{
    private readonly ConcurrentDictionary<string, List<ECDsa>> _keys = new(StringComparer.Ordinal);

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

        return key.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

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
