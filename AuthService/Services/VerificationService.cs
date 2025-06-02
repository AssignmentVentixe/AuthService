using AuthService.Interfaces;

namespace AuthService.Services;

public class VerificationService(IHttpClientFactory httpClientFactory) : IVerificationService
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    public async Task<bool> VerifyCodeAsync(string email, string code)
    {
        var client = _httpClientFactory.CreateClient("EmailVerificationProvider");
        var payload = new { Email = email, Code = code };
        var resp = await client.PostAsJsonAsync("api/verification/verify", payload);

        if (!resp.IsSuccessStatusCode)
            return false;

        return true;
    }
}
