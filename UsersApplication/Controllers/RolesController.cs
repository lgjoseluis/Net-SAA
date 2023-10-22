using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UsersApplication.Constants;
using UsersApplication.Data;

namespace UsersApplication.Controllers
{
    [Authorize(Roles = StringValues.ROLE_ADMIN)]
    public class RolesController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;

        public RolesController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _context = context;
        }

        [HttpGet]
        public IActionResult Index()
        {
            var roles = _context.Roles.ToList();

            return View(roles);
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(IdentityRole model)
        {
            if( await _roleManager.RoleExistsAsync(model.Name))
            {
                TempData["RoleError"] = $"El rol {model.Name} ya existe";

                return RedirectToAction(nameof(Index));
            }

            await _roleManager.CreateAsync(new IdentityRole() { Name = model.Name });

            TempData["RoleSuccess"] = $"El rol {model.Name} se ha creado correctamente";

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public IActionResult Edit(string id)
        {
            if(string.IsNullOrEmpty(id))
                return View();

            IdentityRole rol = _context.Roles.FirstOrDefault(r => r.Id == id);

            return View(rol);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(IdentityRole model)
        {
            if (await _roleManager.RoleExistsAsync(model.Name))
            {
                TempData["RoleError"] = $"El rol {model.Name} ya existe";

                return RedirectToAction(nameof(Index));
            }

            IdentityRole role = _context.Roles.FirstOrDefault(r => r.Id == model.Id);

            if (role is null)
            {
                TempData["RoleError"] = $"El rol no se puede recuperar";

                return RedirectToAction(nameof(Index));
            }

            role.Name = model.Name;
            role.NormalizedName = model.Name.ToUpper();

            await _roleManager.UpdateAsync(role);

            TempData["RoleSuccess"] = $"El rol {role.Name} se actualizó correctamente";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string id)
        {
            IdentityRole role = _context.Roles.FirstOrDefault(r => r.Id == id);

            if (role is null)
            {
                TempData["RoleError"] = $"El rol no existe";

                return RedirectToAction(nameof(Index));
            }

            bool usersInRole = _userManager.GetUsersInRoleAsync(role.Name).Result.Any();

            if (usersInRole)
            {
                TempData["RoleError"] = $"No se puede borrar el rol {role.Name}, tiene usuarios";

                return RedirectToAction(nameof(Index));
            }

            await _roleManager.DeleteAsync(role);

            TempData["RoleSuccess"] = $"El rol {role.Name} se borró correctamente";

            return RedirectToAction(nameof(Index));
        }
    }
}
