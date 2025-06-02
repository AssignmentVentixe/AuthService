using AuthService.Interfaces;

namespace AuthService.Services;

public class EmailService(IHttpClientFactory httpClientFactory) : IEmailService
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    public async Task SendEmailAsync(string email)
    {
        var client = _httpClientFactory.CreateClient("EmailVerificationProvider");

        var payload = new { Email = email };

        var resp = await client.PostAsJsonAsync("api/verification/send", payload);
        resp.EnsureSuccessStatusCode();
    }
}