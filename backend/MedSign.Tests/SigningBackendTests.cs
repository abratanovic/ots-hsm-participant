using System.Security.Cryptography;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
using Microsoft.Extensions.DependencyInjection;

namespace MedSign.Tests;

/// <summary>
/// Where the signing keys live is a deployment decision, and this is the test
/// that it stays one: the same application code has to work whether a YubiHSM
/// or AWS KMS is behind the interface, and the tests must never find out which
/// by asking the internet.
/// </summary>
public class SigningBackendTests
{
    [Fact]
    public void The_test_host_never_signs_in_the_cloud()
    {
        using var host = new MedSignHost();

        // Not a style check. A suite that reached AWS would fail on a bad network,
        // cost money, and need credentials nobody running these tests has.
        Assert.IsType<EnvJwtSigningProvider>(host.Services.GetRequiredService<IJwtSigningProvider>());
        Assert.IsType<FakeDocumentSigner>(host.Services.GetRequiredService<IDocumentSigner>());
    }
}

/// <summary>
/// AWS KMS speaks DER; MedSign stores r||s and 0x04||X||Y. These conversions are
/// the only KMS-specific logic with anywhere to hide a bug, and both are pure
/// functions, so they are tested here rather than against the real service.
/// </summary>
public class DerConversionTests
{
    private const int Coordinate = 32;

    [Fact]
    public void A_DER_signature_still_verifies_once_it_is_r_and_s()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var digest = SHA256.HashData("a report worth signing"u8.ToArray());

        var der = key.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);

        var raw = DerConversions.ToFixedWidthSignature(der, Coordinate);

        Assert.Equal(2 * Coordinate, raw.Length);
        Assert.True(key.VerifyHash(digest, raw, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void Holds_up_across_many_signatures_not_just_a_lucky_one()
    {
        // r or s comes out shorter than 32 bytes roughly once in 256, and DER
        // drops those leading zeros. A conversion that forgot to pad would pass
        // a single-signature test and then fail in front of an audience.
        for (var attempt = 0; attempt < 300; attempt++)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var digest = RandomNumberGenerator.GetBytes(Coordinate);

            var raw = DerConversions.ToFixedWidthSignature(
                key.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence), Coordinate);

            Assert.Equal(2 * Coordinate, raw.Length);
            Assert.True(
                key.VerifyHash(digest, raw, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                $"attempt {attempt} produced a signature that no longer verifies");
        }
    }

    [Fact]
    public void Pads_a_short_coordinate_instead_of_shifting_it_left()
    {
        // r = 1, s = 2: one byte each in DER, and both belong at the far right of
        // their 32-byte field. Left-aligning them would be a valid-looking
        // 64 bytes that verifies against nothing.
        byte[] der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];

        var raw = DerConversions.ToFixedWidthSignature(der, Coordinate);

        Assert.Equal(2 * Coordinate, raw.Length);
        Assert.Equal(1, raw[Coordinate - 1]);
        Assert.Equal(2, raw[^1]);
        Assert.All(raw[..(Coordinate - 1)], b => Assert.Equal(0, b));
    }

    [Fact]
    public void Drops_the_sign_byte_DER_adds_to_a_high_coordinate()
    {
        // A coordinate whose top bit is set gets a leading 0x00 in DER so it does
        // not read as negative. That byte is DER's, not the number's.
        byte[] r = [0x00, 0xFF, .. new byte[31]];
        byte[] s = [0x01, .. new byte[31]];

        byte[] der = [0x30, (byte)(4 + r.Length + s.Length),
                      0x02, (byte)r.Length, .. r,
                      0x02, (byte)s.Length, .. s];

        var raw = DerConversions.ToFixedWidthSignature(der, Coordinate);

        Assert.Equal(2 * Coordinate, raw.Length);
        Assert.Equal(0xFF, raw[0]);
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x02, 0x01, 0x01 })]                    // an INTEGER, no SEQUENCE
    [InlineData(new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00 })] // trailing byte
    public void Refuses_what_is_not_a_DER_signature(byte[] notASignature)
    {
        Assert.Throws<InvalidOperationException>(
            () => DerConversions.ToFixedWidthSignature(notASignature, Coordinate));
    }

    [Fact]
    public void Turns_a_DER_public_key_into_the_point_MedSign_stores()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var expected = key.ExportParameters(includePrivateParameters: false);

        var point = DerConversions.ToUncompressedPoint(key.ExportSubjectPublicKeyInfo());

        Assert.Equal(EcPoint.UncompressedP256Bytes, point.Length);
        Assert.Equal(0x04, point[0]);
        Assert.Equal(expected.Q.X, EcPoint.X(point));
        Assert.Equal(expected.Q.Y, EcPoint.Y(point));
    }

    [Fact]
    public void A_converted_public_key_verifies_what_its_private_half_signed()
    {
        // The two conversions meeting: a signature that arrived as DER, checked
        // against a public key that arrived as DER. This is the whole KMS path,
        // minus the network.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var digest = SHA256.HashData("h.novak"u8.ToArray());

        var raw = DerConversions.ToFixedWidthSignature(
            key.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence), Coordinate);

        using var verifier = EcPoint.Verifier(
            DerConversions.ToUncompressedPoint(key.ExportSubjectPublicKeyInfo()));

        Assert.True(verifier.VerifyHash(digest, raw, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void Refuses_a_public_key_from_a_curve_MedSign_cannot_store()
    {
        // A P-384 key is a perfectly good key and a 97-byte point. Slicing the
        // first 65 bytes off one would look like success and verify nothing.
        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        Assert.Throws<InvalidOperationException>(
            () => DerConversions.ToUncompressedPoint(wrongCurve.ExportSubjectPublicKeyInfo()));
    }
}
