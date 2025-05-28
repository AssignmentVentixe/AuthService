namespace AuthService.Interfaces;

public interface IVerificationService
{
    Task<bool> VerifyCodeAsync(string email, string code);
}