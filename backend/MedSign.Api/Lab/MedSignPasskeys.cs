using Fido2NetLib;
using Fido2NetLib.Objects;
using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Data;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Lab;

public sealed class MedSignPasskeys(IFido2 fido2, PasskeyChallengeStore challenges, MedSignDb db)
{
    public CredentialCreateOptions BeginRegistration(string username, string fullName)
    {
        // TODO 1/8: Build CredentialCreateOptions, issue the registration
        // ceremony under the normalized username, and return the options.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Lab/MedSignPasskeys.cs#L14-L41
        throw new NotImplementedException(
            "Exercise 1/8: start the registration ceremony in MedSignPasskeys.BeginRegistration.");
    }

    public async Task<RegisteredPasskey> CompleteRegistrationAsync(
        string username,
        PasskeyRegistration credential)
    {
        // TODO 3/8: Consume the original ceremony, verify the browser response,
        // reject duplicate credential IDs, and return the verified public data.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Lab/MedSignPasskeys.cs#L43-L69
        throw new NotImplementedException(
            "Exercise 3/8: complete the registration ceremony in MedSignPasskeys.CompleteRegistrationAsync.");
    }

    public async Task<AssertionOptions> BeginSignInAsync(string username)
    {
        // TODO 5/8: Load the account, offer only its credential IDs, issue a
        // fresh assertion ceremony, and still answer unknown usernames safely.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Lab/MedSignPasskeys.cs#L71-L84
        throw new NotImplementedException(
            "Exercise 5/8: start the sign-in ceremony in MedSignPasskeys.BeginSignInAsync.");
    }

    public async Task<VerifiedAssertion?> CompleteSignInAsync(
        string username,
        PasskeyAssertion? assertion)
    {
        // TODO 7/8: Consume the assertion ceremony, find the stored credential,
        // verify the signature, counter, RP context and user handle, then return
        // the account, credential and new signature counter.
        // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Lab/MedSignPasskeys.cs#L86-L116
        throw new NotImplementedException(
            "Exercise 7/8: complete the sign-in ceremony in MedSignPasskeys.CompleteSignInAsync.");
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
