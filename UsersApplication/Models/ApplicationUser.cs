﻿using Microsoft.AspNetCore.Identity;

namespace UsersApplication.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; }

        public DateTime BirthDate { get; set; }

        public string Country { get; set; } 

        public string City { get; set; }
    }
}
