namespace MedSign.Api.Shared.Auth;

/// <summary>
/// What MedSign made of a presented token: an identity, or the reason there
/// isn't one. Exactly one of the two is set.
/// </summary>
public sealed record SessionReview(SessionPrincipal? Session, string? Problem)
{
    public static SessionReview Accepted(SessionPrincipal session) => new(session, null);

    public static SessionReview Refused(string problem) => new(null, problem);
}
