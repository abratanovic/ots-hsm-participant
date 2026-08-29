namespace MedSign.Api.Shared.Auth;

/// <summary>
/// Where <see cref="SessionMiddleware"/> leaves what it read, and how an
/// endpoint asks for it.
/// </summary>
public static class SessionAccess
{
    private const string SessionItem = "medsign.session";
    private const string RefusalItem = "medsign.session.refusal";

    internal static void Attach(this HttpContext context, SessionReview review, ILogger log)
    {
        if (review.Session is { } session)
        {
            context.Items[SessionItem] = session;
            return;
        }

        context.Items[RefusalItem] = review.Problem;

        log.LogInformation("Ignoring the token on {Method} {Path}: {Problem}",
            context.Request.Method, context.Request.Path, review.Problem);
    }

    /// <summary>The caller's session, or null when they presented none MedSign accepted.</summary>
    public static SessionPrincipal? TrySession(this HttpContext context) =>
        context.Items.TryGetValue(SessionItem, out var session) ? session as SessionPrincipal : null;

    /// <summary>
    /// The caller's session, on an endpoint that declared it needs one.
    ///
    /// Throwing here would mean an endpoint asked for a session without
    /// requiring a role, which is a wiring mistake rather than a bad request.
    /// </summary>
    public static SessionPrincipal Session(this HttpContext context) =>
        context.TrySession() ?? throw new InvalidOperationException(
            $"{context.Request.Path} read the session without requiring a role. "
            + "Add .RequireRole(...) to the endpoint: the guard is what makes the session non-null.");

    /// <summary>Why the presented token was not accepted, when one was presented.</summary>
    public static string? SessionRefusal(this HttpContext context) =>
        context.Items.TryGetValue(RefusalItem, out var refusal) ? refusal as string : null;
}
