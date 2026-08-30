using MedSign.Api.Hsm;

namespace MedSign.Api.Tokens;

public interface IJwtSigningProvider
{
    string Name { get; }

    JwtSigningKey ProvisionSigningKey(string label);

    byte[] SignDigest(string label, byte[] digest);
}
