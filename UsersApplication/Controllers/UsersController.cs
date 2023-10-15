using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UsersApplication.Data;
using UsersApplication.Models;
using UsersApplication.ViewModels;

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

        public IActionResult Index()
        {
            return View();
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
    }
}
