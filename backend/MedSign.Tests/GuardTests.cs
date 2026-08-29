using System.Security.Cryptography;
using System.Text;
using MedSign.Api.Shared;

namespace MedSign.Tests;

/// <summary>
/// Base64url is not base64: WebAuthn and JWT both reject padding and both reject
/// '+' and '/'. Every credential id and every token segment on the wire goes
/// through here, so a slip is a total outage, not a cosmetic one.
/// </summary>
public class Base64UrlTests
{
    [Fact]
    public void Encode_leaves_no_padding_and_no_unsafe_characters()
    {
        var encoded = Base64Url.Encode(new byte[] { 0xFB, 0xFF, 0xBE, 0x01 });

        Assert.DoesNotContain('=', encoded);
        Assert.DoesNotContain('+', encoded);
        Assert.DoesNotContain('/', encoded);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(32)]
    [InlineData(65)]
    public void Round_trips_every_padding_case(int length)
    {
        var original = RandomNumberGenerator.GetBytes(length);

        Assert.Equal(original, Base64Url.Decode(Base64Url.Encode(original)));
    }

    [Fact]
    public void Decodes_a_value_produced_elsewhere()
    {
        // "MedSign" in base64url, unpadded, as a browser would send it.
        Assert.Equal("MedSign", Encoding.UTF8.GetString(Base64Url.Decode("TWVkU2lnbg")));
    }
}

/// <summary>
/// A P-256 public key on the wire is 0x04 followed by X and Y. Storing the raw
/// PKCS#11 attribute instead -- which is DER-wrapped -- is the classic exercise 2
/// mistake, and it produces a JWKS that verifies nothing.
/// </summary>
public class EcPointTests
{
    private static byte[] Point(byte first = 0x04) => [first, .. RandomNumberGenerator.GetBytes(64)];

    [Fact]
    public void Accepts_an_uncompressed_point()
    {
        EcPoint.EnsureUncompressedP256(Point());
    }

    [Fact]
    public void Rejects_a_point_that_is_the_wrong_length()
    {
        var tooShort = new byte[33];
        tooShort[0] = 0x04;

        var failure = Assert.Throws<InvalidOperationException>(
            () => EcPoint.EnsureUncompressedP256(tooShort));

        Assert.Contains("65", failure.Message);
    }

    [Fact]
    public void Rejects_a_compressed_point()
    {
        Assert.Throws<InvalidOperationException>(() => EcPoint.EnsureUncompressedP256(Point(0x02)));
    }

    [Fact]
    public void Unwrap_strips_the_der_octet_string_around_the_point()
    {
        var point = Point();
        byte[] wrapped = [0x04, 0x41, .. point];

        Assert.Equal(point, EcPoint.Unwrap(wrapped));
    }

    [Fact]
    public void Unwrap_leaves_a_bare_point_alone()
    {
        var point = Point();

        Assert.Equal(point, EcPoint.Unwrap(point));
    }

    [Fact]
    public void Splits_into_two_32_byte_coordinates()
    {
        var point = Point();

        Assert.Equal(32, EcPoint.X(point).Length);
        Assert.Equal(32, EcPoint.Y(point).Length);
        Assert.Equal(point[1..33], EcPoint.X(point));
    }
}

public class RolesTests
{
    [Theory]
    [InlineData("doctor")]
    [InlineData("patient")]
    public void Knows_the_three_MedSign_roles(string role) => Assert.True(Roles.IsKnown(role));

    [Theory]
    [InlineData("Doctor")]
    [InlineData("admin")]
    [InlineData("")]
    [InlineData(null)]
    public void Rejects_anything_else(string? role) => Assert.False(Roles.IsKnown(role));
}
