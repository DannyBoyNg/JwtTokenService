namespace DannyBoyNg.Services
{
    /// <summary>
    /// Default interface for refresh tokens
    /// </summary>
    public interface IRefreshToken
    {
        /// <summary>
        /// Gets or sets the token.
        /// </summary>
        string Token { get; set; }
        /// <summary>
        /// Gets or sets the user identifier.
        /// </summary>
        int UserId { get; set; }
    }
}