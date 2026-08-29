namespace MedSign.Api.Shared;

/// <summary>
/// There is nothing here for this caller.
///
/// Deliberately one exception for two different situations -- the thing does
/// not exist, and the thing is not theirs -- because the answer to both has to
/// be the same document. A 403 on a report a stranger asked for would confirm
/// that the report exists, which is to say that the patient named in the URL
/// they guessed has medical records. The status is the leak, so the status is
/// what has to be identical.
///
/// It follows <see cref="BadRequestException"/>'s shape: raised where the data
/// is, mapped to a status by <see cref="ProblemMiddleware"/>, so an endpoint
/// never has to remember which refusal it owes whom.
/// </summary>
public sealed class NotFoundException(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}
