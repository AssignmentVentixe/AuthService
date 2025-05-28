using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using AuthService.Interfaces;

namespace AuthService.Services;

public class EmailService(IHttpClientFactory httpClientFactory) : IEmailService
{
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    public async Task SendEmailAsync(string email)
    {
        // Skapa named client (samma namn som i Program.cs)
        var client = _httpClientFactory.CreateClient("EmailVerificationProvider");

        // Paketera e-postadressen i ett objekt enligt din VerificationController
        var payload = new { Email = email };

        // Anropa microservicen
        var resp = await client.PostAsJsonAsync("api/verification/send", payload);
        resp.EnsureSuccessStatusCode();
    }
}