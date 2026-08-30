using Microsoft.Extensions.Options;

namespace MedSign.Api.Hsm.Reports;

public sealed class ReportStorageOptions
{
    public string Root { get; set; } = "data";
}

public sealed class ReportStorage(IOptions<ReportStorageOptions> options)
{
    public const string Reports = "reports";

    public string Directory => Path.Combine(options.Value.Root, Reports);

    public string PathFor(Guid publicId) => Path.Combine(Directory, $"{publicId}.pdf");

    public void EnsureDirectory() => System.IO.Directory.CreateDirectory(Directory);

    public void Write(Guid publicId, byte[] pdf)
    {
        EnsureDirectory();

        File.WriteAllBytes(PathFor(publicId), pdf);
    }

    public byte[]? TryRead(Guid publicId)
    {
        var path = PathFor(publicId);

        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    public void Discard(Guid publicId)
    {
        var path = PathFor(publicId);

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
