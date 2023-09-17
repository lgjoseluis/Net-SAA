using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UsersApplication.Models;

namespace UsersApplication.Data
{
    public class ApplicationDbContext : IdentityDbContext
    {
        #region Models
        
        public DbSet<ApplicationUser> ApplicationUsers { get; set; }        
        
        #endregion

        public ApplicationDbContext(DbContextOptions options):base(options)
        {
            
        }
    }
}
