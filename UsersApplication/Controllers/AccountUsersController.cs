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

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel data)
        {
            if (ModelState.IsValid)
            {
                Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(data.Email, data.Password, data.RememberMe, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }

                ModelState.AddModelError(string.Empty, "Acceso no válido");
            }

            return View(data);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LogOut() 
        { 
            await _signInManager.SignOutAsync();

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
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
