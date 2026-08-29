using System.Text.Json;

namespace MedSign.Api.Shared;

/// <summary>
/// The one refusal shape MedSign puts on the wire: a status, a title and a
/// detail, as application/problem+json.
///
/// <see cref="ProblemMiddleware"/> writes it for the exceptions that escape a
/// handler, and the session guards write it for the requests that never reach
/// one -- so "you are not signed in" and "the HSM is down" look alike to the
/// frontend's error mapping, which is the only reason it can have one.
/// </summary>
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

    /// <summary>The same document, for a filter that refuses before the handler runs.</summary>
    public static IResult Result(int status, string title, string detail) =>
        Results.Text(Body(status, title, detail), ContentType, statusCode: status);

    private static string Body(int status, string title, string detail) =>
        JsonSerializer.Serialize(new { status, title, detail });
}
