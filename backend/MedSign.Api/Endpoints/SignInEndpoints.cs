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

            // TODO 6/8: Start a fresh assertion ceremony, convert its binary
            // fields for JSON, and return the challenge without leaking whether
            // this username exists.
            // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Passkeys/Endpoints/SignInEndpoints.cs#L13-L33
            throw new NotImplementedException(
                "Exercise 6/8: implement the sign-in-challenge endpoint.");
        })
        .WithName("StartPasskeySignIn");

        group.MapPost("/sign-in", async (
            SignInRequest request,
            MedSignDb db,
            MedSignPasskeys passkeys,
            SessionIssuer sessions,
            ILogger<Program> log) =>
        {
            // TODO 8/8: Normalize the username, verify the assertion, return one
            // generic 401 response for every refusal, persist the new signature
            // counter, and issue the JWT session only after successful verification.
            // Solution: https://github.com/blockchain-lab-um/ots-hsm-participant/blob/solution/backend/MedSign.Api/Passkeys/Endpoints/SignInEndpoints.cs#L35-L68
            throw new NotImplementedException(
                "Exercise 8/8: implement the sign-in endpoint.");
        })
        .WithName("SignIn");
    }
}
