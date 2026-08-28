using Fido2NetLib;
using Fido2NetLib.Exceptions;
using MedSign.Api.Auth;
using MedSign.Api.Auth.Passkey;
using MedSign.Api.Data;
using MedSign.Api.Lab;
using static MedSign.Api.Endpoints.AuthResults;

namespace MedSign.Api.Endpoints;

public static class SignInEndpoints
{
    public static void MapSignInEndpoints(this IEndpointRouteBuilder group)
    {
        group.MapPost("/sign-in-challenge", async (
            PasskeyChallengeRequest request,
            MedSignPasskeys passkeys) =>
        {
            if (string.IsNullOrWhiteSpace(request.Username))
            {
                return Results.BadRequest(new
                {
                    status = StatusCodes.Status400BadRequest,
                    title = "No username",
                    detail = "A username is required to look up which passkeys may answer.",
                });
            }

            var username = Normalise(request.Username);

            var options = await passkeys.BeginSignInAsync(username);

            return Results.Ok(PasskeyWire.ToWire(options));
        })
        .WithName("StartPasskeySignIn");

        group.MapPost("/sign-in", async (
            SignInRequest request,
            MedSignDb db,
            MedSignPasskeys passkeys,
            SessionIssuer sessions,
            ILogger<Program> log) =>
        {
            var username = Normalise(request.Username ?? string.Empty);

            VerifiedAssertion? verified;
            try
            {
                verified = await passkeys.CompleteSignInAsync(username, request.Assertion);
            }
            catch (Fido2VerificationException exception)
            {
                return Rejected(log, username, exception.Message);
            }

            if (verified is null)
            {
                return Rejected(log, username,
                    "no live challenge, unknown account, or unknown credential");
            }

            verified.Credential.SignCount = verified.SignCount;
            await db.SaveChangesAsync();

            log.LogInformation("Signed in: {Username} ({Role})",
                verified.Account.Username, verified.Account.Role);

            return Results.Ok(sessions.Issue(verified.Account));
        })
        .WithName("SignIn");
    }
}
