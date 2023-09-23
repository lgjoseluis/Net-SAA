using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UsersApplication.Models;
using UsersApplication.ViewModels;

namespace UsersApplication.Controllers
{
    public class AccountUsersController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AccountUsersController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register()
        {
            RegisterViewModel registerVM = new();

            return View(registerVM);
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel data)
        {
            if(ModelState.IsValid)
            {
                ApplicationUser user = new ApplicationUser { 
                    UserName = data.Email,
                    Email = data.Email,
                    FullName = data.FullName,
                    Country = data.Country,
                    City = data.City,
                    PhoneNumber = data.PhoneNumber,
                    BirthDate = data.BirthDate.Value
                };

                IdentityResult result = await _userManager.CreateAsync(user, data.Password);

                if(result.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return RedirectToAction("Index", "Home");
                }

                ValidarErrores(result);
            }

            return View(data);
        }

        private void ValidarErrores(IdentityResult result) 
        {
            foreach (IdentityError error in result.Errors) 
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }
    }
}
