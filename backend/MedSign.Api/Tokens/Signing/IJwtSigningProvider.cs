using MedSign.Api.Hsm;

namespace MedSign.Api.Tokens;

/// <summary>
/// Where the key that signs MedSign's access tokens lives, and how it is used.
///
/// The private key never crosses this interface in either direction: a provider
/// hands back the public point and signs digests on request. That is what makes
/// exercise 2 a swap rather than a rewrite -- the .env implementation keeps the
/// key where anyone can read it, the HSM implementation keeps it where nobody
/// can, and nothing above this line can tell the difference.
///
/// This is deliberately about JWTs and nothing else. Anything else the HSM signs
/// talks to HsmCommunicator directly.
/// </summary>
public interface IJwtSigningProvider
{
    string Name { get; }

    JwtSigningKey ProvisionSigningKey(string label);

    byte[] SignDigest(string label, byte[] digest);
}
