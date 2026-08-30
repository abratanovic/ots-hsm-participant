using MedSign.Api.Shared;

namespace MedSign.Api.Passkeys;

internal static class AuthResults
{
    public static string Normalise(string username) => username.Trim().ToLowerInvariant();

    public static IResult? Validate(string? username, string? fullName, string? role)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(fullName))
        {
            return Problem(StatusCodes.Status400BadRequest, "Incomplete registration",
                "A username and a full name are both required.");
        }

        if (!Roles.IsKnown(role))
        {
            return Problem(StatusCodes.Status400BadRequest, "Unknown role",
                $"Role must be one of: {Roles.All}.");
        }

        return null;
    }

    public static IResult Taken(string username) =>
        Problem(StatusCodes.Status409Conflict, "Username already registered",
            $"'{username}' already has a MedSign Cloud account.");

    public static IResult AlreadyRegistered() =>
        Problem(StatusCodes.Status409Conflict, "That passkey is already registered",
            "This device already holds a MedSign passkey. Sign in with it instead.");

    public static IResult Rejected(ILogger log, string username, string reason)
    {
        log.LogWarning("Sign-in refused for {Username}: {Reason}", username, reason);

        return Problem(StatusCodes.Status401Unauthorized, "Sign-in failed", detail: null);
    }

    private const string ProblemJson = "application/problem+json";

    private static IResult Problem(int status, string title, string? detail) => detail is null
        ? Results.Json(new { status, title }, statusCode: status, contentType: ProblemJson)
        : Results.Json(new { status, title, detail }, statusCode: status, contentType: ProblemJson);
}
