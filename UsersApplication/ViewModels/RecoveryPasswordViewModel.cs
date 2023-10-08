using System.ComponentModel.DataAnnotations;

namespace UsersApplication.ViewModels
{
    public class RecoveryPasswordViewModel
    {
        [Required(ErrorMessage = "El email es obligatorio")]
        [EmailAddress]
        public string Email { get; set; }
    }
}
