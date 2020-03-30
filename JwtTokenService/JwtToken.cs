namespace DannyBoyNg.Services
{
    public class JwtToken
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public string TokenType { get; set; } = "bearer";
    }
}
