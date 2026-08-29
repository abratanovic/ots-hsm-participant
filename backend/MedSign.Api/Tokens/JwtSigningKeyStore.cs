using MedSign.Api.Shared;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Tokens;

public sealed class JwtSigningKeyStore(MedSignDb db, IJwtSigningProvider provider) : IJwtSigningKeyStore
{
    public JwtSigningKey? Current() => db.JwtSigningKeys
        .AsNoTracking()
        .SingleOrDefault(key => key.Provider == provider.Name);

    public void Register(JwtSigningKey key)
    {
        EnsureSameProvider(key);

        if (Current() is not null)
        {
            throw new InvalidOperationException(
                $"A JWT Signing Key is already registered on {provider.Name}.");
        }

        db.JwtSigningKeys.Add(key);
        db.SaveChanges();
    }

    public void Replace(JwtSigningKey key)
    {
        EnsureSameProvider(key);

        var stale = db.JwtSigningKeys.Where(existing => existing.Provider == provider.Name);
        db.JwtSigningKeys.RemoveRange(stale);
        db.JwtSigningKeys.Add(key);
        db.SaveChanges();
    }

    private void EnsureSameProvider(JwtSigningKey key)
    {
        if (key.Provider != provider.Name)
        {
            throw new InvalidOperationException(
                $"The key says it was provisioned on '{key.Provider}' but the active Provider is "
                + $"'{provider.Name}'. Set JwtSigningKey.Provider to the Provider that actually holds "
                + "the private key -- it is how this key is found again.");
        }
    }
}
