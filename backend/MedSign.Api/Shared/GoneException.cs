namespace MedSign.Api.Shared;

public sealed class GoneException(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}
