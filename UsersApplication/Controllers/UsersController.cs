using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Data;
using System.Security.Claims;
using UsersApplication.Claims;
using UsersApplication.Constants;
using UsersApplication.Data;
using UsersApplication.Models;
using UsersApplication.ViewModels;
using static UsersApplication.ViewModels.UserClaimsViewModel;

namespace UsersApplication.Controllers
{
    [Authorize]
    public class UsersController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _context;

        public UsersController(UserManager<IdentityUser> userManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        [HttpGet]
        [Authorize(Policy = StringValues.Policies.ADMINISTRATOR)]
        public async Task<IActionResult> Index()
        {
            List<ApplicationUser> users = await _context.ApplicationUsers.ToListAsync();
            List<IdentityUserRole<string>> userRoles =  await _context.UserRoles.ToListAsync();
            List<IdentityRole> roles = await _context.Roles.ToListAsync();

            foreach (ApplicationUser user in users)
            {
                IdentityUserRole<string> role = userRoles.Find( u => u.UserId == user.Id);

                user.Role = "Niguno";

                if (role is not null)
                {
                    user.Role = roles.Find(u => u.Id == role.RoleId).Name;
                }
            }

            return View(users);
        }

        [HttpGet]
        public IActionResult EditProfile(string id) 
        {
            if (string.IsNullOrEmpty(id))
            {
                return BadRequest();
            }

            ApplicationUser user = _context.ApplicationUsers.Find(id);

            if (user is null)
            {
                return NotFound();
            }

            return View(user);

        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditProfile(ApplicationUser model)
        {
            if(ModelState.IsValid)
            {
                ApplicationUser user = await _context.ApplicationUsers.FindAsync(model.Id);

                user.FullName = model.FullName;
                user.Country = model.Country;
                user.City = model.City;
                user.BirthDate = model.BirthDate;
                user.PhoneNumber = model.PhoneNumber;

                await _userManager.UpdateAsync(user);

                return RedirectToAction(nameof(Index), "Home");
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model, string email)
        {
            if (ModelState.IsValid)
            {
                IdentityUser user = await _userManager.FindByEmailAsync(email);

                if(user is null)
                {
                    return RedirectToAction("Error"); 
                }

                string token = await _userManager.GeneratePasswordResetTokenAsync(user);

                IdentityResult result = await _userManager.ResetPasswordAsync(user, token, model.Password);

                if (result.Succeeded)
                {
                    return RedirectToAction("ConfirmChangePassword");
                }

                return View(model);
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ConfirmChangePassword()
        {
            return View();
        }

        [HttpGet]
        [Authorize(Policy = StringValues.Policies.ADMIN_EDIT)]
        public IActionResult Edit(string id)
        {
            ApplicationUser user = _context.ApplicationUsers.FirstOrDefault(u => u.Id == id);

            if (user is null)
            {
                return NotFound();
            }

            List<IdentityUserRole<string>> usersRoles = _context.UserRoles.ToList();
            List<IdentityRole> roles =  _context.Roles.ToList();
            IdentityUserRole<string> role = usersRoles.Find(u => u.UserId == user.Id);

            if(role is not null)
            {
                user.RoleId = roles.Find(u => u.Id == role.RoleId).Id;
            }

            user.RoleList = roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem 
            { 
                Text = u.Name,
                Value = u.Id
            });

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = StringValues.Policies.ADMIN_EDIT)]
        public async Task<IActionResult> Edit(ApplicationUser model)
        {
            if (ModelState.IsValid)
            {
                ApplicationUser user = _context.ApplicationUsers.FirstOrDefault(u => u.Id == model.Id);

                if (user is null)
                {
                    return NotFound();
                }

                string newRole = _context.Roles.FirstOrDefault(u => u.Id == model.RoleId)!.Name;

                IdentityUserRole<string> role = _context.UserRoles.FirstOrDefault(u => u.UserId == user.Id);

                if (role is not null)
                {
                    string currentRole = _context.Roles.Where(u => u.Id == role.RoleId).Select(e => e.Name).FirstOrDefault();

                    await _userManager.RemoveFromRoleAsync(user, currentRole);
                }                
                
                await _userManager.AddToRoleAsync(user, newRole);

                return RedirectToAction(nameof(Index));
            }
                        
            model.RoleList = _context.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = StringValues.ROLE_ADMIN)]
        public IActionResult LockUnlock(string userId)
        {          
            ApplicationUser user = _context.ApplicationUsers.FirstOrDefault(u => u.Id == userId);

            if (user is null)
            {
                return NotFound();
            }

            if(user.LockoutEnd is not null && user.LockoutEnd > DateTime.Now) //User locked
            {
                user.LockoutEnd = DateTime.Now;
                TempData["UserSuccess"] = $"El usuario {user.FullName} se ha bloqueado correctamente";
            }
            else 
            {
                user.LockoutEnd = DateTime.Now.AddYears(100);
                TempData["UserSuccess"] = $"El usuario {user.FullName} se ha desbloqueado correctamente";
            }

            _context.SaveChanges();

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = StringValues.ROLE_ADMIN)]
        public IActionResult Delete(string id)
        {
            ApplicationUser user = _context.ApplicationUsers.FirstOrDefault(u => u.Id == id);

            if (user is null)
            {
                return NotFound();
            }

            _context.ApplicationUsers.Remove(user);
            _context.SaveChanges();
            TempData["UserSuccess"] = $"El usuario {user.FullName} se ha borrado correctamente";

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> ManageClaims(string id)
        { 
            IdentityUser user = await _userManager.FindByIdAsync(id);

            if (user is null)
                return NotFound();

            IList<Claim> userClaims = await _userManager.GetClaimsAsync(user);

            UserClaimsViewModel model = new UserClaimsViewModel() { 
                UserId = id
            };

            foreach (Claim claim in CatalogClaims.EditClaims)             
            {
                UserClaim userClaim = new UserClaim() { 
                    ClaimType = claim.Type,
                    Selected = userClaims.Any(c => c.Type == claim.Type)
                };

                model.Claims.Add(userClaim);
            }

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageClaims(UserClaimsViewModel model)
        {
            IdentityUser user = await _userManager.FindByIdAsync(model.UserId);

            if (user is null)
                return NotFound();

            IList<Claim> userClaims = await _userManager.GetClaimsAsync(user);

            IdentityResult result = await _userManager.RemoveClaimsAsync(user, userClaims);

            if (!result.Succeeded)
            { 
                return View(model);
            }

            IEnumerable<Claim> newClaims = model.Claims.Where(c => c.Selected).Select( s => new Claim(s.ClaimType, s.Selected.ToString()));

            result = await _userManager.AddClaimsAsync(user, newClaims);

            if (!result.Succeeded)
            {
                return View(model);
            }

            return RedirectToAction(nameof(Index));
        }
    }
}