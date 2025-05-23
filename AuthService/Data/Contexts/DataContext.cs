using AuthService.Data.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Data.Contexts;

public class DataContext(DbContextOptions<DataContext> options) : IdentityDbContext<AppUser>(options)
{

}