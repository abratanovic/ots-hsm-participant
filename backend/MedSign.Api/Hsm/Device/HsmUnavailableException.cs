namespace MedSign.Api.Hsm.Device;

public sealed class HsmUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);
