using Amazon;
using Amazon.Runtime;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using MedSign.Api.Hsm.Device;
using MedSign.Api.Shared;
using Microsoft.Extensions.Options;
using NotFoundException = Amazon.KeyManagementService.Model.NotFoundException;

namespace MedSign.Api.Cloud.Kms;

/// <summary>
/// The AWS KMS counterpart of HsmCommunicator.
///
/// Same three operations, same P-256 keys, same digest in and signature out.
/// What changes is everything around them: the key sits in a region rather than
/// on a desk, the caller proves itself with an IAM identity rather than a PIN,
/// and every signature is a network round trip that AWS records in CloudTrail.
///
/// This class is given, not an exercise. It exists so the swap can be shown to
/// be a deployment decision rather than an architectural one -- MedSignPasskeys,
/// the report pipeline and the JWKS endpoint are all untouched by it.
/// </summary>
public sealed class KmsCommunicator : IDisposable
{
    private readonly KmsOptions _options;
    private readonly ILogger<KmsCommunicator> _log;
    private readonly IAmazonKeyManagementService _kms;
    private bool _disposed;

    public KmsCommunicator(IOptions<KmsOptions> options, ILogger<KmsCommunicator> log)
    {
        _options = options.Value;
        _log = log;

        // RegionEndpoint.GetBySystemName invents an endpoint for a name it does
        // not know rather than refusing, so a typo here would surface minutes
        // later as a DNS failure. Catch it while the message can still say why.
        if (string.IsNullOrWhiteSpace(_options.Region))
        {
            throw new InvalidOperationException(
                "Kms:Region is empty. Set AWS_REGION to the region holding the key, for example "
                + "eu-west-1.");
        }

        // Credentials are not passed in code. The SDK reads them from the
        // environment, which is how they reach the container from .env -- the
        // same reason the YubiHSM PIN is not in appsettings either.
        _kms = new AmazonKeyManagementServiceClient(
            RegionEndpoint.GetBySystemName(_options.Region));

        if (_options.UsesSingleKey)
        {
            _log.LogWarning(
                "AWS KMS is pinned to one key for every label ({KeyId}). Fine for a demonstration; "
                + "in a deployment each label would be its own alias, so a report's fingerprint "
                + "still says which doctor signed it.",
                _options.KeyId);
        }
    }

    /// <summary>The public point of the key behind this label, or null when there is none.</summary>
    public byte[]? GetKey(string label)
    {
        var address = _options.Address(label);

        try
        {
            var response = Call(() => _kms.GetPublicKeyAsync(new GetPublicKeyRequest
            {
                KeyId = address,
            }));

            EnsureUsable(response.KeySpec, response.KeyUsage, address);

            // KMS answers with a DER SubjectPublicKeyInfo; MedSign stores 0x04||X||Y.
            return DerConversions.ToUncompressedPoint(response.PublicKey.ToArray());
        }
        catch (NotFoundException)
        {
            return null;
        }
    }

    /// <summary>Creates a P-256 signing key and gives this label to it.</summary>
    public byte[] CreateKey(string label)
    {
        if (!_options.AllowKeyCreation)
        {
            throw new HsmUnavailableException(
                $"There is no KMS key for '{label}', and creating one is switched off. A KMS key is "
                + "billed monthly and cannot be deleted on the day -- scheduled deletion waits days -- "
                + "so a room full of participants creating keys is a bill and a week of cleanup. "
                + "Point Kms:KeyId at a key that already exists, or set Kms:AllowKeyCreation=true "
                + "if you meant it.");
        }

        if (_options.UsesSingleKey)
        {
            throw new HsmUnavailableException(
                $"Kms:KeyId pins every label to one key, so there is nothing to create for '{label}'. "
                + $"The key it names ({_options.KeyId}) could not be read -- check the region "
                + $"({_options.Region}), the ARN, and that the caller may call kms:GetPublicKey.");
        }

        var created = Call(() => _kms.CreateKeyAsync(new CreateKeyRequest
        {
            KeySpec = KeySpec.ECC_NIST_P256,
            KeyUsage = KeyUsageType.SIGN_VERIFY,
            Description = $"MedSign Cloud signing key for {label}",
        }));

        var keyId = created.KeyMetadata.KeyId;

        // A KMS key has no label of its own. An alias is how a name is attached,
        // and it is a second call: the key exists before it can be found by name.
        Call(() => _kms.CreateAliasAsync(new CreateAliasRequest
        {
            AliasName = $"alias/{label}",
            TargetKeyId = keyId,
        }));

        _log.LogInformation(
            "Created a P-256 signing key on AWS KMS: {KeyId} as alias/{Label}. It is billed monthly "
            + "and scheduled deletion waits days, so remember it exists.",
            keyId, label);

        // Read the public half back by key id rather than by the alias just
        // created: aliases are eventually consistent, and a first read through
        // one can miss. That would look like flakiness in enrolment and is not.
        var fresh = Call(() => _kms.GetPublicKeyAsync(new GetPublicKeyRequest { KeyId = keyId }));

        return DerConversions.ToUncompressedPoint(fresh.PublicKey.ToArray());
    }

    /// <summary>Signs an already-hashed 32-byte digest and returns r||s.</summary>
    public byte[] SignDigest(string label, byte[] digest)
    {
        ArgumentNullException.ThrowIfNull(digest);

        if (digest.Length != Pkcs11Constants.P256CoordinateBytes)
        {
            throw new InvalidOperationException(
                $"AWS KMS expects exactly the {Pkcs11Constants.P256CoordinateBytes}-byte SHA-256 "
                + $"digest when MessageType is DIGEST, got {digest.Length} bytes.");
        }

        var response = Call(() => _kms.SignAsync(new SignRequest
        {
            KeyId = _options.Address(label),
            Message = new MemoryStream(digest),

            // DIGEST, not RAW: the caller has already hashed. Sending a digest as
            // RAW would have KMS hash it a second time, and the signature would
            // verify against nothing anybody else computes.
            MessageType = MessageType.DIGEST,
            SigningAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256,
        }));

        // KMS returns DER. A JWS is defined over r||s, and TokenVerifier refuses
        // anything else -- so the envelope comes off here and nowhere else.
        return DerConversions.ToFixedWidthSignature(
            response.Signature.ToArray(), Pkcs11Constants.P256CoordinateBytes);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _kms.Dispose();
    }

    private static void EnsureUsable(KeySpec? spec, KeyUsageType? usage, string address)
    {
        if (spec != KeySpec.ECC_NIST_P256 || usage != KeyUsageType.SIGN_VERIFY)
        {
            throw new HsmUnavailableException(
                $"The KMS key {address} is {spec}/{usage}. MedSign signs with ES256, so it needs "
                + $"{KeySpec.ECC_NIST_P256} and {KeyUsageType.SIGN_VERIFY}.");
        }
    }

    /// <summary>
    /// Runs one KMS call, turning the ways AWS can say no into the failure the
    /// rest of the application already understands.
    ///
    /// ProblemMiddleware maps HsmUnavailableException to 503, which is the right
    /// answer for both a device that is unplugged and a cloud that is
    /// unreachable: the request could not be served, and trying again may work.
    /// </summary>
    private T Call<T>(Func<Task<T>> call)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            return call().GetAwaiter().GetResult();
        }
        catch (NotFoundException)
        {
            throw;
        }
        catch (AmazonKeyManagementServiceException exception)
        {
            throw new HsmUnavailableException(
                $"AWS KMS refused the request in {_options.Region}: {exception.Message} "
                + "Check the key state, the region, and that the caller's IAM identity may use it.",
                exception);
        }
        catch (AmazonServiceException exception)
        {
            throw new HsmUnavailableException(
                $"Could not reach AWS KMS in {_options.Region}: {exception.Message} "
                + "Check network access and whether the credentials have expired.",
                exception);
        }
    }
}
