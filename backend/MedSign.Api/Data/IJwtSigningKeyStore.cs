namespace MedSign.Api.Data;

public interface IJwtSigningKeyStore
{
    JwtSigningKey? Current();

    void Register(JwtSigningKey key);

    void Replace(JwtSigningKey key);
}
