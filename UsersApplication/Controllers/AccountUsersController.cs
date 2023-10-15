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

                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticatorCode), new { returnUrl, data.RememberMe });
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

        [HttpGet]
        public async Task<IActionResult> ActivateAuthenticator()
        {
            IdentityUser user = await _userManager.GetUserAsync(User);

            await _userManager.ResetAuthenticatorKeyAsync(user);

            string token = await _userManager.GetAuthenticatorKeyAsync(user);

            return View(
                new TwoFactorAuthenticationViewModel() { Token = token }
            );
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ActivateAuthenticator(TwoFactorAuthenticationViewModel model)
        {
            if (ModelState.IsValid) 
            {
                IdentityUser user = await _userManager.GetUserAsync(User);
                bool succeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

                if (succeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else 
                {
                    ModelState.AddModelError("Error", "Su autenticación de dos factores no se ha validado");
                    return View(model);
                }
            }

            return RedirectToAction(nameof(ConfirmAuthenticator));
        }

        [HttpGet]
        public IActionResult ConfirmAuthenticator()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberData, string returnUrl = null)
        {
            IdentityUser user = await _signInManager.GetTwoFactorAuthenticationUserAsync();

            if (user is null)
            {
                return View("Error");
            }

            ViewData["ReturnUrl"] = returnUrl;

            return View( new VerifyAuthenticatorCodeViewModel() { ReturnUrl = returnUrl, RememberData = rememberData});
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorCodeViewModel model)
        {
            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");

            if (!ModelState.IsValid) 
            {
                return View(model);
            }

            Microsoft.AspNetCore.Identity.SignInResult result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code,model.RememberData, rememberClient:true);

            if (result.Succeeded) 
            {
                return LocalRedirect(model.ReturnUrl);
            }
            else if (result.IsLockedOut)
            {
                return View("UserBlocked");
            }

            ModelState.AddModelError(String.Empty, "Código inválido");

            return View(model);
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
