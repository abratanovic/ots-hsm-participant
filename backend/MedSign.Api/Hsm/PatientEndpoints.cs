using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm;

public static class PatientEndpoints
{
    public static void MapPatientEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/patients", (MedSignDb db, CancellationToken cancellationToken) =>
            db.Users
                .AsNoTracking()
                .Where(user => user.Role == Roles.Patient)
                .OrderBy(user => user.DisplayName)
                .Select(user => new
                {
                    id = user.Id,
                    username = user.Username,
                    fullName = user.DisplayName,
                })
                .ToListAsync(cancellationToken))
            .RequireRole(Roles.Doctor)
            .WithName("GetPatients");
    }
}
