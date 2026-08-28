using MedSign.Api.Data;

namespace MedSign.Api.Hsm;

public interface ISigningProvider
{
    string Name { get; }

    JwtSigningKey ProvisionSigningKey(string label);

    byte[] SignDigest(string label, byte[] digest);
}
