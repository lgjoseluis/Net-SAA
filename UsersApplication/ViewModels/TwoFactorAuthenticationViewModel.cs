using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace UsersApplication.ViewModels
{
    public class TwoFactorAuthenticationViewModel
    {
        [Required]
        [Display(Name = "Código del autenticador")]
        public string Code { get; set; }

        public string Token { get; set; }
    }
}
