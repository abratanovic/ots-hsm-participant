namespace MedSign.Api.Shared;

public sealed class BadRequestException(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}
