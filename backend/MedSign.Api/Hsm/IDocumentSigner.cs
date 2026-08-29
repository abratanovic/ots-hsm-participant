namespace MedSign.Api.Hsm;

/// <summary>
/// The device's key-generation and signing operations, as the document-signing
/// side of MedSign uses them.
///
/// This exists for one reason: a YubiHSM has no simulator and no container, so
/// without a seam here every path that issues or verifies a report could only
/// be tested with hardware plugged in -- and the test gate blocks the backend
/// from starting, so those tests could never be written at all.
///
/// <see cref="IJwtSigningProvider"/> carries a comment saying it is about JWTs
/// and nothing else, and that anything else the HSM signs should talk to
/// <see cref="HsmCommunicator"/> directly. This is a deliberate departure from
/// that, agreed rather than overlooked: the two interfaces stay separate, so
/// swapping the JWT provider between .env and the HSM -- which is exercise 2 --
/// still has nothing to do with the key a doctor signs documents with.
///
/// The private key does not cross this interface in either direction.
/// </summary>
public interface IDocumentSigner
{
    /// <summary>The public point of the key stored under this label, or null if there is none.</summary>
    byte[]? FindKey(string label);

    /// <summary>
    /// Generates a non-exportable P-256 key pair under this label and returns
    /// the public point, uncompressed.
    /// </summary>
    byte[] CreateKey(string label);

    /// <summary>Signs an already-computed digest, returning raw R||S.</summary>
    byte[] SignDigest(string label, byte[] digest);
}

/// <summary>The real one. Every method is the communicator's, unchanged.</summary>
public sealed class HsmDocumentSigner(HsmCommunicator hsm) : IDocumentSigner
{
    public byte[]? FindKey(string label) => hsm.GetKey(label);

    public byte[] CreateKey(string label) => hsm.CreateKey(label);

    public byte[] SignDigest(string label, byte[] digest) => hsm.SignDigest(label, digest);
}
