namespace AuthService.Interfaces;

public interface IEmailService
{
    Task SendEmailAsync(string email);
}