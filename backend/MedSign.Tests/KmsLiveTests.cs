using System.Security.Cryptography;
using MedSign.Api.Cloud.Kms;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MedSign.Tests;

/// <summary>
/// The one test that talks to AWS, and therefore the one test that is skipped
/// unless somebody deliberately asks for it.
///
/// Everything else about the KMS path is covered offline by DerConversionTests,
/// because it is all pure functions. What cannot be covered offline is whether
/// the real service, the real credentials and the real key agree with what this
/// code believes about them -- and that is exactly what breaks in front of an
/// audience. Run it as the rehearsal:
///
///   AWS_REGION=... AWS_KMS_KEY_ID=... AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
///     dotnet test backend/MedSign.slnx
///
/// Without those variables it reports as skipped and costs nothing.
/// </summary>
public class KmsLiveTests
{
    private static (string Region, string KeyId)? Configured()
    {
        var region = Environment.GetEnvironmentVariable("AWS_REGION");
        var keyId = Environment.GetEnvironmentVariable("AWS_KMS_KEY_ID");

        return string.IsNullOrWhiteSpace(region) || string.IsNullOrWhiteSpace(keyId)
            ? null
            : (region, keyId);
    }

    private static KmsCommunicator Kms((string Region, string KeyId) settings) =>
        new(Options.Create(new KmsOptions
        {
            Region = settings.Region,
            KeyId = settings.KeyId,
        }), NullLogger<KmsCommunicator>.Instance);

    [Fact]
    public void Signs_a_digest_that_the_published_public_key_verifies()
    {
        if (Configured() is not { } settings)
        {
            Assert.Skip("Set AWS_REGION and AWS_KMS_KEY_ID to run the live KMS check.");
            return;
        }

        using var kms = Kms(settings);

        var point = kms.GetKey("medsign-jwt-signing");
        Assert.NotNull(point);
        EcPoint.EnsureUncompressedP256(point);

        var digest = SHA256.HashData("a report worth signing"u8.ToArray());
        var signature = kms.SignDigest("medsign-jwt-signing", digest);

        // The whole reason DerConversions exists. KMS answers in DER; a JWS is
        // defined over r||s, and TokenVerifier refuses anything else. If this
        // assertion ever fails, sign-in fails too -- with a message about
        // "70 bytes starting with 0x30".
        Assert.Equal(2 * Pkcs11Constants.P256CoordinateBytes, signature.Length);

        using var verifier = EcPoint.Verifier(point);
        Assert.True(
            verifier.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            "AWS KMS signed the digest, but the signature does not verify against the key it "
            + "published. That is the DER-to-r||s conversion, not the service.");
    }

    [Fact]
    public void Serves_the_document_signer_the_report_pipeline_uses()
    {
        if (Configured() is not { } settings)
        {
            Assert.Skip("Set AWS_REGION and AWS_KMS_KEY_ID to run the live KMS check.");
            return;
        }

        using var kms = Kms(settings);

        // The other half of the swap. ReportIssuing signs the PDF's digest
        // through IDocumentSigner, and DoctorSigningKeys enrols a doctor through
        // FindKey -- so both have to work against the real service, not just the
        // JWT provider that happens to share a communicator.
        IDocumentSigner signer = new KmsDocumentSigner(kms);

        var label = DoctorKeyLabel.For(doctorUserId: 1);

        var point = signer.FindKey(label);
        Assert.NotNull(point);

        var digest = SHA256.HashData("a rendered report"u8.ToArray());
        var signature = signer.SignDigest(label, digest);

        Assert.Equal(2 * Pkcs11Constants.P256CoordinateBytes, signature.Length);

        using var verifier = EcPoint.Verifier(point);
        Assert.True(
            verifier.VerifyHash(digest, signature, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            "The document signer produced a signature the enrolled key does not verify.");
    }
}
