using System.ComponentModel.DataAnnotations;

namespace UsersApplication.ViewModels
{
    public class VerifyAuthenticatorCodeViewModel
    {
        [Required]
        [Display(Name = "Código del autenticador")]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }
                
        [Display(Name = "¿Recordar datos?")]
        public bool RememberData { get; set; }
    }
}
