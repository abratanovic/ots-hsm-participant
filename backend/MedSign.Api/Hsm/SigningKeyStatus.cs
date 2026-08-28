using System.Runtime.ExceptionServices;

namespace MedSign.Api.Hsm;

public sealed class SigningKeyStatus
{
    private ExceptionDispatchInfo? _failure;

    public Exception? ProvisioningFailure => _failure?.SourceException;

    public void RecordFailure(Exception failure) =>
        _failure = ExceptionDispatchInfo.Capture(failure);

    public Exception SigningKeyMissing(string providerName)
    {
        _failure?.Throw();

        return new InvalidOperationException(
            $"JWT signing is not provisioned on {providerName}, so MedSign Cloud cannot issue an "
            + "access token. The key is created at startup -- restart the backend.");
    }
}
