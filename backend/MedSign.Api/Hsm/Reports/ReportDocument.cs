using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace MedSign.Api.Hsm.Reports;

public sealed record ReportContent(
    DateTimeOffset IssuedAt,
    string DoctorName,
    string PatientName,
    string Type,
    string Body);

public static class ReportDocument
{
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

    private static void Footnote(IContainer container) => container
        .PaddingTop(1, Unit.Centimetre)
        .Text("Signed by the issuing doctor's key on MedSign's hardware security module. "
            + "The signature is held with the record and verified through MedSign.")
        .FontSize(8).FontColor(Colors.Grey.Darken1);
}
