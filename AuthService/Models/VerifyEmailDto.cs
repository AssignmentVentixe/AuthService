using System.ComponentModel.DataAnnotations;

namespace AuthService.Models;

public class VerifyEmailDto
{
    [Required]
    public string Email { get; set; } = null!;

    [Required]
    public string Code { get; set; } = null!;
}