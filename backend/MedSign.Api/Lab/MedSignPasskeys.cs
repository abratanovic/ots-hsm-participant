using System.Security.Cryptography;
using Fido2NetLib;
using Fido2NetLib.Objects;
using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Data;
using Microsoft.EntityFrameworkCore;
using Fido2AuthenticatorSelection = Fido2NetLib.AuthenticatorSelection;

namespace MedSign.Api.Lab;

public sealed class MedSignPasskeys(IFido2 fido2, PasskeyChallengeStore challenges, MedSignDb db)
{
    public CredentialCreateOptions BeginRegistration(string username, string fullName)
    {
        var options = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User
            {
                Id = RandomNumberGenerator.GetBytes(32),
                Name = username,
                DisplayName = fullName.Trim(),
            },

            PubKeyCredParams = [PubKeyCredParam.ES256],

            AuthenticatorSelection = new Fido2AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Preferred,
                UserVerification = UserVerificationRequirement.Preferred,
            },

            AttestationPreference = AttestationConveyancePreference.None,

            ExcludeCredentials = [],
        });

        challenges.Issue(username, options);

        return options;
    }

    public async Task<RegisteredPasskey> CompleteRegistrationAsync(
        string username,
        PasskeyRegistration credential)
    {
        var options = challenges.ConsumeRegistration(username)
            ?? throw new InvalidOperationException(
                "There is no outstanding registration ceremony for that username. It has already "
                + "been used, or it expired. Start registration again -- a challenge is single-use "
                + "precisely so that a captured one cannot be replayed.");

        var registered = await fido2.MakeNewCredentialAsync(
            new MakeNewCredentialParams
            {
                AttestationResponse = PasskeyWire.ToRaw(credential),
                OriginalOptions = options,
                IsCredentialIdUniqueToUserCallback = async (unique, _) =>
                    !await db.PasskeyCredentials.AnyAsync(
                        existing => existing.CredentialId == unique.CredentialId),
            });

        return new RegisteredPasskey(
            options.User.Id,
            new VerifiedCredential(
                registered.Id,
                CosePublicKey.ToPoint(registered.PublicKey),
                registered.SignCount));
    }

    public async Task<AssertionOptions> BeginSignInAsync(string username)
    {
        var user = await FindAccountAsync(username);

        var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = user is null ? [] : [.. user.Credentials.Select(Descriptor)],
            UserVerification = UserVerificationRequirement.Preferred,
        });

        challenges.Issue(username, options);

        return options;
    }

    public async Task<VerifiedAssertion?> CompleteSignInAsync(
        string username,
        PasskeyAssertion? assertion)
    {
        var options = challenges.ConsumeAssertion(username);

        var user = await FindAccountAsync(username);
        var stored = FindCredential(user, assertion?.RawId);

        if (options is null || user is null || stored is null)
        {
            return null;
        }

        var result = await fido2.MakeAssertionAsync(
            new MakeAssertionParams
            {
                AssertionResponse = PasskeyWire.ToRaw(assertion!),

                OriginalOptions = options,

                StoredPublicKey = CosePublicKey.FromPoint(stored.PublicKeyPoint),

                StoredSignatureCounter = (uint)stored.SignCount,

                IsUserHandleOwnerOfCredentialIdCallback = (owner, _) => Task.FromResult(
                    CryptographicOperations.FixedTimeEquals(owner.UserHandle, user.Handle)),
            });

        return new VerifiedAssertion(user, stored, result.SignCount);
    }

    private Task<User?> FindAccountAsync(string username) =>
        db.Users
            .Include(candidate => candidate.Credentials)
            .SingleOrDefaultAsync(candidate => candidate.Username == username);

    private static PasskeyCredential? FindCredential(User? user, string? rawId)
    {
        var credentialId = TryDecode(rawId);

        return credentialId is null
            ? null
            : user?.Credentials.SingleOrDefault(
                credential => credential.CredentialId.SequenceEqual(credentialId));
    }

    private static PublicKeyCredentialDescriptor Descriptor(PasskeyCredential credential) =>
        new(PublicKeyCredentialType.PublicKey,
            credential.CredentialId,
            string.IsNullOrEmpty(credential.Transports)
                ? null
                : WebAuthnEnums.Transports(credential.Transports.Split(',')));

    private static byte[]? TryDecode(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            return Base64Url.Decode(value);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
