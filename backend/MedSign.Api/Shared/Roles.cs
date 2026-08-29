namespace MedSign.Api.Shared;

public static class Roles
{
    public const string Doctor = "doctor";
    public const string Patient = "patient";

    public static bool IsKnown(string? role) => role is Doctor or Patient;

    public static string All => $"{Doctor}, {Patient}";
}
