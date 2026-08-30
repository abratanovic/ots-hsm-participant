using System.Text.Json;

namespace MedSign.Api.Shared;

public static class Problem
{
    public const string ContentType = "application/problem+json";

    public static async Task WriteAsync(HttpContext context, int status, string title, string detail)
    {
        if (context.Response.HasStarted)
        {
            return;
        }

        context.Response.Clear();
        context.Response.StatusCode = status;
        context.Response.ContentType = ContentType;

        await context.Response.WriteAsync(Body(status, title, detail));
    }

    public static IResult Result(int status, string title, string detail) =>
        Results.Text(Body(status, title, detail), ContentType, statusCode: status);

    private static string Body(int status, string title, string detail) =>
        JsonSerializer.Serialize(new { status, title, detail });
}
