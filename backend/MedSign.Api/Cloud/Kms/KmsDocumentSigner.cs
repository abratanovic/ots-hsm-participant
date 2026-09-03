using MedSign.Api.Hsm.Device;

namespace MedSign.Api.Cloud.Kms;

/// <summary>
/// Reports signed in AWS KMS instead of on the YubiHSM.
///
/// Deliberately identical to HsmDocumentSigner line for line. Everything above
/// this interface -- enrolling a doctor, issuing a report, verifying one later --
/// is the same code either way, and that is the entire argument.
/// </summary>
public sealed class KmsDocumentSigner(KmsCommunicator kms) : IDocumentSigner
{
    public byte[]? FindKey(string label) => kms.GetKey(label);

    public byte[] CreateKey(string label) => kms.CreateKey(label);

    public byte[] SignDigest(string label, byte[] digest) => kms.SignDigest(label, digest);
}
