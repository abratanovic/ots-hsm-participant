using System.Security.Cryptography;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Hsm.Reports;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Tokens;

/// <summary>
/// Doctor signing keys in software, for the provider that keeps the JWT key in
/// an environment variable.
///
/// It exists so that one setting swaps the whole signing layer: 'env' signs
/// sessions and documents, and so do 'hsm' and 'kms'. Otherwise enabling
/// signing on the default provider asks a device that is not there.
///
/// It is also the demonstration. Each key is a file next to the database, so
/// the private half can be read, copied and used elsewhere by anyone who can
/// read the disk -- which is the property the HSM exercises remove. Nothing
/// here checks who is asking, because nothing here can.
/// </summary>
public sealed class EnvDocumentSigner(
    IOptions<ReportStorageOptions> storage,
    ILogger<EnvDocumentSigner> log) : IDocumentSigner
{
    private const string Keys = "signing-keys";

    private string Directory => Path.Combine(storage.Value.Root, Keys);

    private string PathFor(string label) => Path.Combine(Directory, $"{label}.pkcs8");

    public byte[]? FindKey(string label)
    {
        var path = PathFor(label);

        if (!File.Exists(path))
        {
            return null;
        }

        using var ecdsa = Load(path);

        return Point(ecdsa);
    }

    public byte[] CreateKey(string label)
    {
        System.IO.Directory.CreateDirectory(Directory);

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var path = PathFor(label);

        File.WriteAllBytes(path, ecdsa.ExportPkcs8PrivateKey());
        Permit(path);

        log.LogWarning(
            "Generated a P-256 signing key for {Label} and wrote the private half to {Path}. "
            + "Anyone who can read that file can sign in this doctor's name, and nothing in "
            + "MedSign would know. This is the software provider; the HSM and KMS providers "
            + "keep the private half where it cannot be read back.",
            label, path);

        return Point(ecdsa);
    }

    public byte[] SignDigest(string label, byte[] digest)
    {
        var path = PathFor(label);

        if (!File.Exists(path))
        {
            throw new InvalidOperationException(
                $"No signing key for '{label}'. MedSign recorded one as enrolled, but {path} is "
                + "gone -- which is all it took to make every report this doctor signed "
                + "unreproducible. Enable signing again to mint a new one.");
        }

        using var ecdsa = Load(path);

        return ecdsa.SignHash(digest, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static ECDsa Load(string path)
    {
        var ecdsa = ECDsa.Create();

        try
        {
            ecdsa.ImportPkcs8PrivateKey(File.ReadAllBytes(path), out _);
        }
        catch (CryptographicException exception)
        {
            ecdsa.Dispose();

            throw new InvalidOperationException(
                $"{path} is not a PKCS#8 private key any more. A signing key in a file is one "
                + "stray write away from being nothing at all.", exception);
        }

        return ecdsa;
    }

    private static byte[] Point(ECDsa ecdsa)
    {
        var q = ecdsa.ExportParameters(includePrivateParameters: false).Q;

        return [0x04, .. q.X!, .. q.Y!];
    }

    /// <summary>Owner-only, on the platforms that have such a notion.</summary>
    private static void Permit(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
}
