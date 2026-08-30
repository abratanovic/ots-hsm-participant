namespace MedSign.Api.Shared;

public sealed class NotFoundException(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}
