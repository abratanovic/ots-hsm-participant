namespace MedSign.Api.Auth;

public static class Roles
{
    public const string Doctor = "doctor";
    public const string Patient = "patient";
    public const string SecurityAdmin = "security-admin";

    public static bool IsKnown(string? role) => role is Doctor or Patient or SecurityAdmin;

    public static string All => $"{Doctor}, {Patient}, {SecurityAdmin}";
}
