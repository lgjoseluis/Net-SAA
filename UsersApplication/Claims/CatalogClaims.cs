using System.Collections.Immutable;
using System.Security.Claims;

namespace UsersApplication.Claims
{
    public static class CatalogClaims
    {
        public static readonly List<Claim> EditClaims =new List<Claim>()
        { 
            new Claim("Create", "Create"),
            new Claim("Edit", "Edit"),
            new Claim("Delete", "Delete"),
        };
    }
}
