namespace MedSign.Api.Passkeys;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth");

        group.MapRegistrationEndpoints();
        group.MapSignInEndpoints();
    }
}
