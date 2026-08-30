namespace MedSign.Api.Tokens;

public interface IJwtSigningKeyStore
{
    JwtSigningKey? Current();

    void Register(JwtSigningKey key);

    void Replace(JwtSigningKey key);
}
