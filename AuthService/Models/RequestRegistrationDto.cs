using System.ComponentModel.DataAnnotations;

namespace AuthService.Models;

public class RequestRegistrationDto
{
    [Required]
    public string Email { get; set; } = null!;
}