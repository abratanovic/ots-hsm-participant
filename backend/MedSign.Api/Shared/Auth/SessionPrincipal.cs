namespace MedSign.Api.Shared.Auth;

/// <summary>
/// Who the caller is, according to the session token they presented.
///
/// Everything here was read out of a signed payload MedSign issued itself, so
/// an endpoint may act on it without asking the database again -- but it is a
/// snapshot taken at sign-in, not the account as it stands now.
/// </summary>
public sealed record SessionPrincipal(int UserId, string Username, string DisplayName, string Role);
