namespace MedSign.Api.Shared.Auth;

/// <summary>
/// The role an endpoint requires, declared on the route and enforced on the
/// server. A frontend that hides a button is a courtesy; this is the check.
/// </summary>
public static class RoleRequirement
{
    public static TBuilder RequireRole<TBuilder>(this TBuilder builder, params string[] roles)
        where TBuilder : IEndpointConventionBuilder
    {
        builder.AddEndpointFilter(async (invocation, next) =>
        {
            var context = invocation.HttpContext;

            if (context.TrySession() is not { } session)
            {
                return Problem.Result(StatusCodes.Status401Unauthorized, "Sign in first",
                    context.SessionRefusal()
                    ?? "This endpoint needs a session. Send the token sign-in handed you as "
                    + "'Authorization: Bearer <token>'.");
            }

            if (roles.Length > 0 && !roles.Contains(session.Role, StringComparer.Ordinal))
            {
                return Problem.Result(StatusCodes.Status403Forbidden, "That is not yours to do",
                    $"This endpoint is for {string.Join(" or ", roles)}; "
                    + $"you are signed in as {session.Role}.");
            }

            return await next(invocation);
        });

        return builder;
    }
}
