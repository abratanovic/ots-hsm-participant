using Microsoft.Extensions.Options;

namespace MedSign.Api.Hsm;

/// <summary>
/// Where report PDFs live.
///
/// Configuration rather than a constant for two reasons: in the workshop the
/// root is the bind-mounted data directory, which is the only path that
/// survives the file-watching dev loop restarting the container; and in a test
/// it is a directory of that test's own. Redirecting it is all a test needs,
/// which is why there is no abstraction over the file system here.
/// </summary>
public sealed class ReportStorageOptions
{
    /// <summary>
    /// The data directory. Matches the connection string's default, so a local
    /// run puts the database and the documents in the same place; compose
    /// points both at <c>/app/data</c>.
    /// </summary>
    public string Root { get; set; } = "data";
}

/// <summary>
/// The only code that writes or removes a report's PDF.
///
/// It does not regenerate one, and must not learn how. A regenerated PDF is
/// byte-different from the one that was signed, so a rebuild would silently
/// destroy the integrity claim the whole feature exists to make.
/// </summary>
public sealed class ReportStorage(IOptions<ReportStorageOptions> options)
{
    /// <summary>The subdirectory of the data root that holds documents.</summary>
    public const string Reports = "reports";

    public string Directory => Path.Combine(options.Value.Root, Reports);

    /// <summary>
    /// The file for a report, named by its public id. Nothing about the patient
    /// or the doctor is in the path: a directory listing is not a patient list.
    /// </summary>
    public string PathFor(Guid publicId) => Path.Combine(Directory, $"{publicId}.pdf");

    /// <summary>Called at startup, so the first report is not the thing that discovers the root is wrong.</summary>
    public void EnsureDirectory() => System.IO.Directory.CreateDirectory(Directory);

    public void Write(Guid publicId, byte[] pdf)
    {
        EnsureDirectory();

        File.WriteAllBytes(PathFor(publicId), pdf);
    }

    /// <summary>
    /// The stored bytes of a report's document, or null when the file is gone.
    ///
    /// Null rather than an exception because a missing file is a real state
    /// with a real answer: the row survives its document, and what a caller is
    /// owed then is "this cannot be produced", not a stack trace. It is also
    /// the only honest answer -- the bytes that were signed cannot be made
    /// again, so nothing here may fall back to rendering a replacement.
    /// </summary>
    public byte[]? TryRead(Guid publicId)
    {
        var path = PathFor(publicId);

        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    /// <summary>
    /// Removes a document written for a report that then failed to be issued.
    ///
    /// Best effort on purpose: this runs while an exception is on its way up,
    /// and a file that cannot be deleted must not replace the real failure with
    /// a worse one. The caller logs; the orphan is inert either way, because
    /// no row names it.
    /// </summary>
    public void Discard(Guid publicId)
    {
        var path = PathFor(publicId);

        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
