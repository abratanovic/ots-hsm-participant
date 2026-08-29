using MedSign.Api.Shared;
using MedSign.Api.Shared.Auth;
using Microsoft.EntityFrameworkCore;

namespace MedSign.Api.Hsm;

/// <summary>
/// Who a doctor may address a report to.
///
/// Doctors are left out deliberately rather than incidentally: the list is what
/// the frontend's recipient picker is built from, and a doctor in it is an
/// invitation to file somebody's findings against a colleague's account.
/// </summary>
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
