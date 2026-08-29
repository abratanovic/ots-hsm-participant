using MedSign.Api.Passkeys;
using MedSign.Api.Tokens;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Shared;

public sealed class MedSignDb(DbContextOptions<MedSignDb> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();
    public DbSet<JwtSigningKey> JwtSigningKeys => Set<JwtSigningKey>();

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
