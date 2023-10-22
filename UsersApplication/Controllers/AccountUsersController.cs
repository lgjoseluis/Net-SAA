using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;
using UsersApplication.Constants;
using UsersApplication.Models;
using UsersApplication.ViewModels;

namespace UsersApplication.Controllers
{
    [Authorize]
    public class AccountUsersController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _urlEncoder;

        public AccountUsersController(UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager,
            RoleManager<IdentityRole> roleManager,
            IEmailSender emailSender,
            UrlEncoder urlEncoder)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailSender = emailSender;
            _urlEncoder = urlEncoder;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            RegisterViewModel registerVM = new();

            return View(registerVM);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
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
        [AllowAnonymous]
        public IActionResult RecoveryPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
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
        [AllowAnonymous]
        public IActionResult ConfirmRecoveryPassword()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code=null)
        {
            return code is null ? View("Error") : View();
        }

        [HttpPost]
        [AllowAnonymous]
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
        [AllowAnonymous]
        public IActionResult ConfirmResetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
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

                if (result.Succeeded)
                {
                    bool roleAdminExists = await _roleManager.RoleExistsAsync(StringValues.ROLE_ADMIN);

                    if (!roleAdminExists)
                    {
                        await _roleManager.CreateAsync(new IdentityRole(StringValues.ROLE_ADMIN));
                    }

                    bool userAdminExists = _userManager.GetUsersInRoleAsync(StringValues.ROLE_ADMIN).Result.Any();

                    if (!userAdminExists)
                    {
                        await _userManager.AddToRoleAsync(user, StringValues.ROLE_ADMIN);
                    }

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
        [AllowAnonymous]
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

            string urlAuthenticator = string.Format(
                    "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
                    _urlEncoder.Encode("Auth Net-SAA"),
                    _urlEncoder.Encode(user.Email),
                    token
                );

            return View(
                new TwoFactorAuthenticationViewModel() { 
                    Token = token,
                    UrlQrCode = urlAuthenticator
                }
            );
        }

        [HttpGet]
        public async Task<IActionResult> DeactivateAuthenticator()
        {
            IdentityUser user = await _userManager.GetUserAsync(User);

            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            
            return RedirectToAction(nameof(Index), "Home");
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
        [AllowAnonymous]
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
        [AllowAnonymous]
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

        [HttpGet]
        public IActionResult UserBlocked()
        {
            return View();
        }

        [HttpGet]
        public IActionResult AcessDenied()
        {
            return View();
        }

        [AllowAnonymous]
        private void ValidarErrores(IdentityResult result) 
        {
            foreach (IdentityError error in result.Errors) 
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }
    }
}
