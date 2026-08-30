using Fido2NetLib;
using Fido2NetLib.Exceptions;
using MedSign.Api.Shared;
using MedSign.Api.Tokens;
using Microsoft.EntityFrameworkCore;
using static MedSign.Api.Passkeys.AuthResults;

namespace MedSign.Api.Passkeys;

public static class RegistrationEndpoints
{
    public static void MapRegistrationEndpoints(this IEndpointRouteBuilder group)
    {
        group.MapPost("/registration-challenge", async (
            AccountDetails details,
            MedSignDb db,
            MedSignPasskeys passkeys) =>
        {
            if (Validate(details.Username, details.FullName, details.Role) is { } invalid)
            {
                return invalid;
            }

            // TODO 2/8: Refuse an existing username, start the registration
            // ceremony, convert its binary fields for JSON, and return HTTP 200.
            // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Passkeys/Endpoints/RegistrationEndpoints.cs#L14-L34
            throw new NotImplementedException(
                "Exercise 2/8: implement the registration-challenge endpoint.");
        })
        .WithName("StartPasskeyRegistration");

        group.MapPost("/registration", async (
            RegisterAccountRequest request,
            MedSignDb db,
            MedSignPasskeys passkeys,
            SessionIssuer sessions,
            TimeProvider clock,
            ILogger<Program> log) =>
        {
            if (Validate(request.Username, request.FullName, request.Role) is { } invalid)
            {
                return invalid;
            }

            // TODO 4/8: Normalize and de-duplicate the username, complete the
            // ceremony, map duplicate credential IDs to HTTP 409, validate the
            // verified key, persist the account and credential, then issue a session.
            // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Passkeys/Endpoints/RegistrationEndpoints.cs#L36-L81
            throw new NotImplementedException(
                "Exercise 4/8: implement the registration endpoint.");
        })
        .WithName("RegisterAccount");
    }

    private static User NewAccount(
        RegisterAccountRequest request,
        string username,
        RegisteredPasskey registered,
        DateTimeOffset now) => new()
        {
            Username = username,
            Handle = registered.UserHandle,
            DisplayName = request.FullName.Trim(),
            Role = request.Role,
            Credentials =
        [
            new PasskeyCredential
            {
                CredentialId = registered.Credential.CredentialId,
                PublicKeyPoint = registered.Credential.PublicKeyPoint,
                SignCount = registered.Credential.SignCount,
                Transports = string.Join(',', request.Credential.Transports),
                CreatedAt = now,
            },
        ],
        };
}
