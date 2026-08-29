namespace MedSign.Api.Shared;

/// <summary>
/// A request MedSign will not fill because of what the caller put in it: a
/// report type that is not one of the four, a body past the limit, a recipient
/// who is not a patient.
///
/// The existing mapping already covers the other refusals -- an
/// <see cref="InvalidOperationException"/> is a state conflict and becomes 409,
/// an <see cref="Hsm.HsmUnavailableException"/> becomes 503 -- and "you sent
/// something wrong" was the one shape missing. Raising it rather than returning
/// a result keeps the validation where the data is: whether a user id names a
/// patient is not a question a route handler can answer.
/// </summary>
public sealed class BadRequestException(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}
