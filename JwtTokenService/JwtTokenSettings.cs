using Microsoft.IdentityModel.Tokens;

namespace DannyBoyNg.Services
{
    public class JwtTokenSettings
    {
        /// <summary>
        /// Set or get when the access token expires.
        /// </summary>
        public int AccessTokenExpirationInMinutes { get; set; } = 60;
        /// <summary>
        /// Set or get when the refresh token expires. Refresh token must expire after access token and not before.
        /// </summary>
        public int RefreshTokenExpirationInHours { get; set; } = 2;
        public TokenValidationParameters? TokenValidationParameters { get; set; }
        public SecurityAlgorithm SecurityAlgorithm { get; set; } = SecurityAlgorithm.HS256;
    }
}
