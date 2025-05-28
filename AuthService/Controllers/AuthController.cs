using AuthService.Data.Entities;
using AuthService.Extensions;
using AuthService.Interfaces;
using AuthService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Text;


namespace AuthService.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IConfiguration config, IEmailService emailService, IVerificationService verificationService) : ControllerBase
{
    private readonly UserManager<AppUser> _userManager = userManager;
    private readonly SignInManager<AppUser> _signInManager = signInManager;
    private readonly IConfiguration _config = config;
    private readonly IEmailService _emailService = emailService;
    private readonly IVerificationService _verificationService = verificationService;

    [HttpPost("request-registration")]
    public async Task<IActionResult> RequestRegistration([FromBody] RequestRegistrationDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (await _userManager.FindByEmailAsync(dto.Email) != null)
            return BadRequest("Email already in use.");

        await _emailService.SendEmailAsync(dto.Email);
        return Ok(new { Message = "Verification email sent." });
    }

    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailDto dto)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var verified = await _verificationService.VerifyCodeAsync(dto.Email, dto.Code);
        if (!verified)
            return BadRequest("Invalid or expired verification code.");

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, dto.Email),
            new Claim("signup", "true")
        };
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(15),
            signingCredentials: creds
        );
        var tokenStr = new JwtSecurityTokenHandler().WriteToken(jwt);

        return Ok(new { SignupToken = tokenStr });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto, [FromHeader(Name = "Authorization")] string? authHeader)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        if (authHeader == null || !authHeader.StartsWith("Bearer "))
            return Unauthorized("Missing signup token.");

        var token = authHeader["Bearer ".Length..].Trim();
        var handler = new JwtSecurityTokenHandler();
        ClaimsPrincipal principal;
        try
        {
            principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(
                                              Encoding.UTF8.GetBytes(_config["JwtKey"]!))
            }, out _);
        }
        catch (SecurityTokenException)
        {
            return Unauthorized("Invalid or expired signup token.");
        }

        var emailInToken = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (emailInToken == null || emailInToken != dto.Email)
            return BadRequest("Email mismatch.");

        var user = dto.MapTo<AppUser>();
        user.UserName = dto.Email;

        var result = await _userManager.CreateAsync(user, dto.Password);
        return result.Succeeded
            ? Ok()
            : BadRequest("Unexpected error");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);



        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return Unauthorized();

        var valid = await _userManager.CheckPasswordAsync(user, dto.Password);
        if (!valid) return Unauthorized();

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);

        var tokenStr = new JwtSecurityTokenHandler().WriteToken(jwt);

        Response.Cookies.Append("jwt", tokenStr, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTimeOffset.UtcNow.AddHours(1)
        });

        return Ok();
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("jwt", new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None
        });

        return Ok();
    }

    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
    {
        var user = HttpContext.User;
        var firstName = user.FindFirst(ClaimTypes.GivenName)?.Value;
        var lastName = user.FindFirst(ClaimTypes.Surname)?.Value;
        var email = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        return Ok(new
        {
            firstName,
            lastName,
            email
        });
    }

}

