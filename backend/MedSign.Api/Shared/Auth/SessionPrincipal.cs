namespace MedSign.Api.Shared.Auth;

public sealed record SessionPrincipal(int UserId, string Username, string DisplayName, string Role);
