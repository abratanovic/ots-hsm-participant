using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace MedSign.Api.Hsm;

/// <summary>
/// What goes on the page.
///
/// A report is rendered once, at the moment it is issued, and the bytes that
/// come out are what gets hashed and signed. So this type takes finished text
/// -- names already resolved from accounts, the type already spelled out for a
/// reader -- and does no lookups of its own. Nothing it renders may depend on
/// when it runs.
/// </summary>
public sealed record ReportContent(
    DateTimeOffset IssuedAt,
    string DoctorName,
    string PatientName,
    string Type,
    string Body);

/// <summary>
/// The rendered medical report: a document that has to stand on its own away
/// from the application, because a patient will keep, print or forward it.
///
/// No font family is named. QuestPDF embeds its own, which is the only way the
/// diacritics in Croatian names survive a container that has no system fonts
/// installed.
/// </summary>
public static class ReportDocument
{
    /// <summary>
    /// Renders a report to PDF bytes.
    ///
    /// The result is never written twice and never regenerated: these exact
    /// bytes are hashed and signed, and a second rendering would not reproduce
    /// them.
    /// </summary>
    public static byte[] Render(ReportContent content) => Document
        .Create(document => document.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(2, Unit.Centimetre);
            page.DefaultTextStyle(text => text.FontSize(11).LineHeight(1.4f));

            page.Header().Element(header => Heading(header, content));
            page.Content().Element(body => Body(body, content));
            page.Footer().Element(Footnote);
        }))
        .GeneratePdf();

    private static void Heading(IContainer container, ReportContent content) => container
        .PaddingBottom(1, Unit.Centimetre)
        .Column(column =>
        {
            column.Item().Text("MedSign Cloud").FontSize(9).FontColor(Colors.Grey.Darken1);

            column.Item().PaddingTop(4).Text(content.Type)
                .FontSize(20).SemiBold();

            column.Item().PaddingTop(2)
                .Text($"Issued {content.IssuedAt:d MMMM yyyy}")
                .FontSize(10).FontColor(Colors.Grey.Darken2);
        });

    private static void Body(IContainer container, ReportContent content) => container
        .Column(column =>
        {
            column.Item().Element(parties => Parties(parties, content));

            column.Item().PaddingTop(1, Unit.Centimetre)
                .Text(content.Body);
        });

    /// <summary>
    /// Who wrote it and who it is about, side by side. Both names came from
    /// accounts MedSign holds; neither was typed into the request.
    /// </summary>
    private static void Parties(IContainer container, ReportContent content) => container
        .BorderTop(1).BorderBottom(1).BorderColor(Colors.Grey.Lighten1)
        .PaddingVertical(12)
        .Row(row =>
        {
            row.RelativeItem().Element(cell => Party(cell, "Patient", content.PatientName));
            row.RelativeItem().Element(cell => Party(cell, "Issued by", content.DoctorName));
        });

    private static void Party(IContainer container, string label, string name) => container
        .Column(column =>
        {
            column.Item().Text(label).FontSize(9).FontColor(Colors.Grey.Darken1);
            column.Item().Text(name).SemiBold();
        });

    /// <summary>
    /// Says where the signature is, because it is not in this file. MedSign
    /// signs the document's digest and stores the signature beside it, so a PDF
    /// reader will not show this as signed and a reader of the paper should not
    /// conclude it is unsigned.
    /// </summary>
    private static void Footnote(IContainer container) => container
        .PaddingTop(1, Unit.Centimetre)
        .Text("Signed by the issuing doctor's key on MedSign's hardware security module. "
            + "The signature is held with the record and verified through MedSign.")
        .FontSize(8).FontColor(Colors.Grey.Darken1);
}
