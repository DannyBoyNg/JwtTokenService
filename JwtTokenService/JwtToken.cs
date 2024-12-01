namespace Ng.JwtTokenService
{
    /// <summary>
    /// A default container for a JWT token
    /// </summary>
    public record JwtToken
    {
        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public string? AccessToken { get; set; }
        /// <summary>
        /// Gets or sets the refresh token.
        /// </summary>
        public string? RefreshToken { get; set; }
        /// <summary>
        /// Gets or sets the type of the token.
        /// </summary>
        public string TokenType { get; set; } = "bearer";
    }
}
