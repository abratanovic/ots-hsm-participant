namespace MedSign.Api.Hsm.Contracts;

public sealed record VerificationView(
    Guid ReportId,
    string Outcome,
    DateTimeOffset CheckedAt,
    string Algorithm,
    PartyView Doctor);
