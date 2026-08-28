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
    // TODO: IMPLEMENT
    public CredentialCreateOptions BeginRegistration(string username, string fullName)
    {
        throw new NotImplementedException("Excercise 1: Implement the registration ceremony. See the localhost:4300 for instructions.");
    }

    // TODO: IMPLEMENT
    public async Task<RegisteredPasskey> CompleteRegistrationAsync(
        string username,
        PasskeyRegistration credential)
    {
        throw new NotImplementedException("Excercise 1: Implement the registration ceremony. See the localhost:4300 for instructions.");
    }

    // TODO: IMPLEMENT
    public async Task<AssertionOptions> BeginSignInAsync(string username)
    {
        throw new NotImplementedException("Excercise 1: Implement the sign-in ceremony. See the localhost:4300 for instructions.");
    }

    // TODO: IMPLEMENT
    public async Task<VerifiedAssertion?> CompleteSignInAsync(
        string username,
        PasskeyAssertion? assertion)
    {
        throw new NotImplementedException("Excercise 1: Implement the sign-in ceremony. See the localhost:4300 for instructions.");
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
