using Fido2NetLib;
using MedSign.Api.Hsm;
using Net.Pkcs11Interop.Common;

namespace MedSign.Api.Shared;

public sealed class ProblemMiddleware(RequestDelegate next, ILogger<ProblemMiddleware> log)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (NotImplementedException ex)
        {
            log.LogInformation("Not implemented yet: {Message}", ex.Message);
            await Write(context, StatusCodes.Status501NotImplemented, "Not implemented yet", ex.Message);
        }
        catch (Fido2VerificationException ex)
        {
            log.LogWarning(ex, "Passkey ceremony refused: {Message}", ex.Message);
            await Write(context, StatusCodes.Status400BadRequest,
                "That passkey ceremony was refused", ex.Message);
        }
        catch (HsmUnavailableException ex)
        {
            log.LogError(ex, "HSM unavailable.");
            await Write(context, StatusCodes.Status503ServiceUnavailable,
                "The HSM is not reachable", ex.Message);
        }
        catch (Pkcs11Exception ex)
        {
            log.LogError(ex, "PKCS#11 call failed with {Rv}.", ex.RV);
            await Write(context, StatusCodes.Status502BadGateway, "The HSM refused the operation",
                $"{ex.Method} returned {ex.RV}.");
        }
        catch (InvalidOperationException ex)
        {
            log.LogWarning(ex, "Rejected: {Message}", ex.Message);
            await Write(context, StatusCodes.Status409Conflict,
                "That cannot be done in this state", ex.Message);
        }
    }

    private static Task Write(HttpContext context, int status, string title, string detail) =>
        Problem.WriteAsync(context, status, title, detail);
}
