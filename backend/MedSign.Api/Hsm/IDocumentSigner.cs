namespace MedSign.Api.Hsm;

public interface IDocumentSigner
{
    byte[]? FindKey(string label);

    byte[] CreateKey(string label);

    byte[] SignDigest(string label, byte[] digest);
}

public sealed class HsmDocumentSigner(HsmCommunicator hsm) : IDocumentSigner
{
    public byte[]? FindKey(string label) => hsm.GetKey(label);

    public byte[] CreateKey(string label) => hsm.CreateKey(label);

    public byte[] SignDigest(string label, byte[] digest) => hsm.SignDigest(label, digest);
}
