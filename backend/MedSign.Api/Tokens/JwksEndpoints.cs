using MedSign.Api.Shared;

namespace MedSign.Api.Tokens;

public static class JwksEndpoints
{
    public static void MapJwksEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/.well-known/jwks.json", (IJwtSigningKeyStore store) =>
        {
            var key = store.Current();
            if (key is null)
            {
                return Results.NotFound(new
                {
                    title = "No JWT Signing Key has been provisioned yet.",
                    detail = "POST /api/provisioning/jwt-signing first.",
                });
            }

            EcPoint.EnsureUncompressedP256(key.EcPoint);

            return Results.Ok(new
            {
                keys = new[]
                {
                    new
                    {
                        kty = "EC",
                        crv = "P-256",
                        alg = "ES256",
                        use = "sig",
                        kid = key.Kid,
                        x = Base64Url.Encode(EcPoint.X(key.EcPoint)),
                        y = Base64Url.Encode(EcPoint.Y(key.EcPoint)),
                    },
                },
            });
        })
        .WithName("GetJwks");
    }
}
