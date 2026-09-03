using System.Security.Cryptography;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Hsm.Reports;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
using Microsoft.Extensions.Logging.Abstractions;

namespace MedSign.Tests;

/// <summary>
/// The software document signer, which is what 'env' uses for a doctor's key.
///
/// It has to satisfy the same contract as the HSM and KMS ones, because the
/// provider is chosen by a single setting and everything above IDocumentSigner
/// is written once: an uncompressed P-256 point out of FindKey and CreateKey,
/// and a signature the stored point verifies.
/// </summary>
public class EnvDocumentSignerTests
{
    /// <summary>A directory that deletes itself; the signer writes real files.</summary>
    private sealed class TempRoot : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(
            System.IO.Path.GetTempPath(), "medsign-env-signer", Guid.NewGuid().ToString("n"));

        public TempRoot() => Directory.CreateDirectory(Path);

        public void Dispose()
        {
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (IOException)
            {
                // A leftover temp directory is not worth failing a test over.
            }
        }
    }

    private static IDocumentSigner NewSigner(TempRoot root) =>
        new EnvDocumentSigner(
            Build.Options(new ReportStorageOptions { Root = root.Path }),
            NullLogger<EnvDocumentSigner>.Instance);

    [Fact]
    public void Has_no_key_until_one_is_made()
    {
        using var root = new TempRoot();
        var signer = NewSigner(root);

        Assert.Null(signer.FindKey("medsign-doctor-1"));
    }

    [Fact]
    public void Makes_a_key_in_the_shape_the_rest_of_MedSign_stores()
    {
        using var root = new TempRoot();
        var signer = NewSigner(root);

        var point = signer.CreateKey("medsign-doctor-1");

        // The same check DoctorSigningKeys runs before it writes the row.
        EcPoint.EnsureUncompressedP256(point);
        Assert.Equal(EcPoint.UncompressedP256Bytes, point.Length);
    }

    [Fact]
    public void Signs_a_digest_the_stored_key_verifies()
    {
        using var root = new TempRoot();
        var signer = NewSigner(root);

        var point = signer.CreateKey("medsign-doctor-1");
        var digest = SHA256.HashData("a rendered report"u8.ToArray());

        var signature = signer.SignDigest("medsign-doctor-1", digest);

        using var verifier = EcPoint.Verifier(point);
        Assert.True(
            verifier.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            "A report signed by this key does not verify against the key MedSign recorded.");
    }

    [Fact]
    public void Keeps_the_same_key_across_restarts()
    {
        using var root = new TempRoot();

        var made = NewSigner(root).CreateKey("medsign-doctor-1");

        // A new instance, as after a restart: the key is on disk, so the doctor's
        // earlier reports still verify against the point already in the database.
        Assert.Equal(made, NewSigner(root).FindKey("medsign-doctor-1"));
    }

    [Fact]
    public void Gives_each_doctor_their_own_key()
    {
        using var root = new TempRoot();
        var signer = NewSigner(root);

        // The fingerprint on a report is only evidence if two doctors cannot share it.
        Assert.NotEqual(signer.CreateKey("medsign-doctor-1"), signer.CreateKey("medsign-doctor-2"));
    }

    [Fact]
    public void Says_so_clearly_when_the_key_file_has_gone()
    {
        using var root = new TempRoot();
        var signer = NewSigner(root);

        signer.CreateKey("medsign-doctor-1");
        File.Delete(Path.Combine(root.Path, "signing-keys", "medsign-doctor-1.pkcs8"));

        var failure = Assert.Throws<InvalidOperationException>(
            () => signer.SignDigest("medsign-doctor-1", new byte[32]));

        Assert.Contains("medsign-doctor-1", failure.Message);
    }
}
