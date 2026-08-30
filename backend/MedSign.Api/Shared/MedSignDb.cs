using MedSign.Api.Hsm;
using MedSign.Api.Passkeys;
using MedSign.Api.Tokens;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Shared;

public sealed class MedSignDb(DbContextOptions<MedSignDb> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
    public DbSet<JwtSigningKey> JwtSigningKeys => Set<JwtSigningKey>();

    public DbSet<SigningKey> SigningKeys => Set<SigningKey>();

    public DbSet<MedicalReport> MedicalReports => Set<MedicalReport>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<User>(user =>
        {
            user.HasKey(u => u.Id);
            user.HasIndex(u => u.Username).IsUnique();
            user.Property(u => u.Username).IsRequired();
            user.Property(u => u.Handle).IsRequired();
            user.Property(u => u.DisplayName).IsRequired();
            user.Property(u => u.Role).IsRequired();

            user.HasOne(u => u.SigningKey)
                .WithMany()
                .HasForeignKey(u => u.SigningKeyId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        model.Entity<SigningKey>(key =>
        {
            key.HasKey(k => k.Id);

            key.HasIndex(k => k.KeyLabel).IsUnique();

            key.Property(k => k.KeyLabel).IsRequired();
            key.Property(k => k.PublicKeyPoint).IsRequired();
        });

        model.Entity<MedicalReport>(report =>
        {
            report.HasKey(r => r.Id);

            report.HasIndex(r => r.PublicId).IsUnique();

            report.Property(r => r.PublicId).IsRequired();
            report.Property(r => r.Type).IsRequired();
            report.Property(r => r.Body).IsRequired();
            report.Property(r => r.FileName).IsRequired();
            report.Property(r => r.Sha256).IsRequired();

            report.Property(r => r.Signature).IsRequired();

            report.HasOne(r => r.Doctor)
                .WithMany()
                .HasForeignKey(r => r.DoctorUserId)
                .OnDelete(DeleteBehavior.Restrict);

            report.HasOne(r => r.Patient)
                .WithMany()
                .HasForeignKey(r => r.PatientUserId)
                .OnDelete(DeleteBehavior.Restrict);

            report.HasOne(r => r.SigningKey)
                .WithMany()
                .HasForeignKey(r => r.SigningKeyId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        model.Entity<PasskeyCredential>(credential =>
        {
            credential.HasKey(c => c.Id);

            credential.HasIndex(c => c.CredentialId).IsUnique();

            credential.Property(c => c.CredentialId).IsRequired();
            credential.Property(c => c.PublicKeyPoint).IsRequired();
            credential.Property(c => c.Transports).IsRequired();

            credential.HasOne(c => c.User)
                .WithMany(u => u.Credentials)
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        model.Entity<JwtSigningKey>(key =>
        {
            key.HasKey(k => k.Id);

            key.HasIndex(k => k.Provider).IsUnique();

            key.Property(k => k.Provider).IsRequired();
            key.Property(k => k.Label).IsRequired();
            key.Property(k => k.EcPoint).IsRequired();
            key.Property(k => k.Kid).IsRequired();
        });
    }
}
