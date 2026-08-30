namespace MedSign.Api.Shared.Auth;

public sealed record SessionReview(SessionPrincipal? Session, string? Problem)
{
    public static SessionReview Accepted(SessionPrincipal session) => new(session, null);

    public static SessionReview Refused(string problem) => new(null, problem);
}
