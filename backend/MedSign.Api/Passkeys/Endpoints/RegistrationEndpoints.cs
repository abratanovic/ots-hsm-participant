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

            var username = Normalise(details.Username);
            if (await db.Users.AnyAsync(user => user.Username == username))
            {
                return Taken(username);
            }

            var options = passkeys.BeginRegistration(username, details.FullName);

            return Results.Ok(PasskeyWire.ToWire(options));
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

            var username = Normalise(request.Username);
            if (await db.Users.AnyAsync(user => user.Username == username))
            {
                return Taken(username);
            }

            RegisteredPasskey registered;
            try
            {
                registered = await passkeys.CompleteRegistrationAsync(username, request.Credential);
            }
            catch (Fido2VerificationException exception)
                when (exception.Code is Fido2ErrorCode.NonUniqueCredentialId)
            {
                return AlreadyRegistered();
            }

            if (PasskeyDiagnostics.DiagnoseRegistration(registered.Credential) is { } problem)
            {
                throw new InvalidOperationException(problem);
            }

            var user = NewAccount(request, username, registered, clock.GetUtcNow());

            db.Users.Add(user);
            await db.SaveChangesAsync();

            log.LogInformation("Account opened: {Username} ({Role}), credential {CredentialId}",
                user.Username, user.Role, Base64Url.Encode(registered.Credential.CredentialId));

            return Results.Ok(sessions.Issue(user));
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
