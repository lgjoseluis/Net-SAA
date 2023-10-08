using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using UsersApplication.Models;
using UsersApplication.ViewModels;

namespace UsersApplication.Controllers
{
    public class AccountUsersController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;

        public AccountUsersController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            RegisterViewModel registerVM = new();

            return View(registerVM);
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel data, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.PasswordSignInAsync(
                    data.Email, 
                    data.Password, 
                    data.RememberMe, 
                    lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    return LocalRedirect(returnUrl);
                }
                else if (result.IsLockedOut) 
                {
                    return View("UserBlocked");
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

        [HttpGet]
        public IActionResult RecoveryPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RecoveryPassword(RecoveryPasswordViewModel model)
        {
            if(ModelState.IsValid)
            {
                IdentityUser user = await _userManager.FindByEmailAsync(model.Email);

                if(user is null)
                {
                    return RedirectToAction("ConfirmRecoveryPassword");
                }

                string code = await _userManager.GeneratePasswordResetTokenAsync(user);

                string urlReturn = Url.Action(
                    "ResetPassword", 
                    "AccountUsers", 
                    new {
                        userId = user.Id,
                        code = code,
                    },
                    HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(
                    model.Email,
                    "Recuperar contraseña|Net-SAA",
                    $"Para recuperar su contraseña de click aqui - <a href=\"{urlReturn}\">enlace</a>"
                );

                return RedirectToAction("ConfirmRecoveryPassword");
            }            

            return View(model);
        }

        [HttpGet]
        public IActionResult ConfirmRecoveryPassword()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string code=null)
        {
            return code is null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                IdentityUser user = await _userManager.FindByEmailAsync(model.Email);

                if (user is null)
                {
                    return RedirectToAction("Error");
                }

                IdentityResult result = await _userManager.ResetPasswordAsync(user,model.Code, model.Password);

                if (result.Succeeded) 
                {
                    return RedirectToAction("ConfirmResetPassword");
                }

                ValidarErrores(result);
            }

            return View(model);
        }

        [HttpGet]
        public IActionResult ConfirmResetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel data, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
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
                    string code = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    string urlReturn = Url.Action(
                    "ConfirmRegister",
                    "AccountUsers",
                    new
                    {
                        userId = user.Id,
                        code = code,
                    },
                    HttpContext.Request.Scheme);

                    await _emailSender.SendEmailAsync(
                        data.Email,
                        "Confirmar registro|Net-SAA",
                        $"Para confirmar su registro de click aqui - <a href=\"{urlReturn}\">enlace</a>"
                    );

                    await _signInManager.SignInAsync(user, isPersistent: false);

                    return LocalRedirect(returnUrl);
                }

                ValidarErrores(result);
            }

            return View(data);
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmRegister(string userId, string code)
        {
            if(string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return View("Error");
            }

            IdentityUser user = await _userManager.FindByIdAsync(userId);

            if (user is null)
            { 
                return View("Error");
            }

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, code);

            return View(result.Succeeded ? "ConfirmRegister": "Error");
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
