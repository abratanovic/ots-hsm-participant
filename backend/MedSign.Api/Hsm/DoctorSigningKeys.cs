using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace MedSign.Api.Hsm;

/// <summary>
/// Enrolment: getting a doctor a document signing key on the device, and
/// answering whether they have one.
///
/// Enabling is idempotent in two layers, because there are two places the
/// answer can already be yes -- the database, and the device.
/// </summary>
public sealed class DoctorSigningKeys(
    MedSignDb db,
    IDocumentSigner signer,
    IOptions<HsmOptions> hsm,
    TimeProvider clock,
    ILogger<DoctorSigningKeys> log)
{
    public SigningKey? For(int doctorUserId) => db.Users
        .AsNoTracking()
        .Where(user => user.Id == doctorUserId)
        .Select(user => user.SigningKey)
        .SingleOrDefault();

    public SigningKey Enable(int doctorUserId)
    {
        var doctor = db.Users
            .Include(user => user.SigningKey)
            .SingleOrDefault(user => user.Id == doctorUserId)
            ?? throw new InvalidOperationException(
                $"There is no account {doctorUserId} to enable signing for.");

        if (doctor.SigningKey is { } enrolled)
        {
            return enrolled;
        }

        var label = DoctorKeyLabel.For(doctorUserId);

        if (label == hsm.Value.KeyLabel)
        {
            throw new InvalidOperationException(
                $"The label for this doctor's key, '{label}', is also the label MedSign's own JWT "
                + "signing key uses. Both keys live in the same token and the device tells them "
                + "apart by label alone, so set Hsm:KeyLabel to something outside the "
                + $"'{DoctorKeyLabel.Prefix}' namespace.");
        }

        var key = db.SigningKeys.SingleOrDefault(existing => existing.KeyLabel == label)
            ?? Provision(label);

        doctor.SigningKey = key;
        db.SaveChanges();

        return key;
    }

    /// <summary>
    /// The key the device is already holding under this label, or a new one.
    ///
    /// Re-adopting rather than regenerating is what makes enabling safe to
    /// repeat, and it has a consequence worth stating: this ticket ships its
    /// schema change by deleting the database file, so the first doctor to
    /// enable signing afterwards silently picks their orphaned key back up off
    /// the device. That is wanted. Generating a second key instead would leave
    /// the first one on the device forever with nothing pointing at it, and
    /// would make every report signed before the reset unverifiable.
    /// </summary>
    private SigningKey Provision(string label)
    {
        var adopted = signer.FindKey(label);

        if (adopted is not null)
        {
            log.LogInformation(
                "Re-adopting the key the HSM already holds under label {Label}.", label);
        }

        var point = adopted ?? signer.CreateKey(label);

        EcPoint.EnsureUncompressedP256(point);

        var key = new SigningKey
        {
            KeyLabel = label,
            PublicKeyPoint = point,
            CreatedAt = clock.GetUtcNow(),
        };

        db.SigningKeys.Add(key);

        return key;
    }
}
