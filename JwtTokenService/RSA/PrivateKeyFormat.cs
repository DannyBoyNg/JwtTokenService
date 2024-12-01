namespace Ng.JwtTokenService.RSA
{
    /// <summary>
    /// Supported private key formats
    /// </summary>
    public enum PrivateKeyFormat
    {
        /// <summary>
        /// PKCS1 format
        /// </summary>
        PKCS1,
        /// <summary>
        /// PKCS8 format
        /// </summary>
        PKCS8,
        /// <summary>
        /// encrypted PKCS8 format
        /// </summary>
        PKCS8Encrypted,
    }
}
