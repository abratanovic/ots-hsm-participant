namespace MedSign.Api.Shared.Auth;

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

    public static SessionPrincipal? TrySession(this HttpContext context) =>
        context.Items.TryGetValue(SessionItem, out var session) ? session as SessionPrincipal : null;

    public static SessionPrincipal Session(this HttpContext context) =>
        context.TrySession() ?? throw new InvalidOperationException(
            $"{context.Request.Path} read the session without requiring a role. "
            + "Add .RequireRole(...) to the endpoint: the guard is what makes the session non-null.");

    public static string? SessionRefusal(this HttpContext context) =>
        context.Items.TryGetValue(RefusalItem, out var refusal) ? refusal as string : null;
}
