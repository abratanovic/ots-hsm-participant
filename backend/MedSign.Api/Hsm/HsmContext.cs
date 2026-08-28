using Net.Pkcs11Interop.HighLevelAPI;

namespace MedSign.Api.Hsm;

public sealed class HsmContext(Func<ISession> connect, Pkcs11InteropFactories factories)
{
    public ISession Session => connect();

    public Pkcs11InteropFactories Factories { get; } = factories;

    public IObjectAttributeFactory Attributes => Factories.ObjectAttributeFactory;

    public IMechanismFactory Mechanisms => Factories.MechanismFactory;
}
