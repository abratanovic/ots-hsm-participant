namespace MedSign.Api.Shared;

/// <summary>
/// The thing was here and is not coming back.
///
/// Distinct from <see cref="NotFoundException"/>, which says nothing about
/// whether a thing exists, and from the 409 an
/// <see cref="InvalidOperationException"/> becomes, which says "not in this
/// state" and so implies a state the caller could reach. A report whose PDF has
/// been deleted is in no such state: those exact bytes are what was signed, a
/// re-rendered document would be byte-different and its signature would no
/// longer verify, so regeneration is not a recovery path and never will be.
/// 410 is the only status that says that truthfully.
/// </summary>
public sealed class GoneException(string title, string detail) : Exception(detail)
{
    public string Title { get; } = title;
}
