﻿using System.ComponentModel.DataAnnotations;

namespace AuthService.Models;

public class RegisterDto
{
    [Required]
    public string Email { get; set; } = null!;

    [Required]
    public string FirstName { get; set; } = null!;

    [Required]
    public string LastName { get; set; } = null!;

    [Required]
    public string Password { get; set; } = null!;
}