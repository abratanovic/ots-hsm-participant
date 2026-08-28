namespace MedSign.Api.Hsm;

public sealed class HsmUnavailableException(string message, Exception? inner = null)
    : Exception(message, inner);
