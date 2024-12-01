using Microsoft.IdentityModel.Tokens;

namespace Ng.JwtTokenService
{
    /// <summary>
    /// JWT token settings container
    /// </summary>
    public record JwtTokenSettings
    {
        /// <summary>
        /// Gets or sets when the access token expires.
        /// </summary>
        public int AccessTokenExpirationInMinutes { get; set; } = 60;
        /// <summary>
        /// Gets or sets when the refresh token expires. Refresh token must expire after access token and not before. Also it cannot be the same duration as an access token because access token have a possible clock skew.
        /// </summary>
        public int RefreshTokenExpirationInHours { get; set; } = 2;
        /// <summary>
        /// Gets or sets the token validation parameters.
        /// </summary>
        public TokenValidationParameters? TokenValidationParameters { get; set; }
        /// <summary>
        /// Gets or sets the security algorithm.
        /// </summary>
        public SecurityAlgorithm SecurityAlgorithm { get; set; } = SecurityAlgorithm.HS256;
    }
}
