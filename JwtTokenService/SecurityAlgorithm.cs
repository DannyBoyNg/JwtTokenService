namespace DannyBoyNg.Services
{
    /// <summary>
    /// Supported SecurityAlgorithm options
    /// </summary>
    public enum SecurityAlgorithm
    {
        /// <summary>
        /// The HS256 (Symmetric) - HMAC Algorithm (HMAC-SHA256)
        /// </summary>
        HS256,
        /// <summary>
        /// The HS384 (Symmetric) - HMAC Algorithm (HMAC-SHA384)
        /// </summary>
        HS384,
        /// <summary>
        /// The HS512 (Symmetric) - HMAC Algorithm (HMAC-SHA512)
        /// </summary>
        HS512,
        /// <summary>
        /// The RS256 (Asymmetric) - RSA Algorithm (RSA-SHA256)
        /// </summary>
        RS256,
        /// <summary>
        /// The RS384 (Asymmetric) - RSA Algorithm (RSA-SHA384)
        /// </summary>
        RS384,
        /// <summary>
        /// The RS512 (Asymmetric) - RSA Algorithm (RSA-SHA512)
        /// </summary>
        RS512,
        /// <summary>
        /// The ES256 (Asymmetric) - Elliptic Curve Digital Signature Algorithm (ECDsa-SHA256)
        /// </summary>
        ES256,
        /// <summary>
        /// The ES384 (Asymmetric) - Elliptic Curve Digital Signature Algorithm (ECDsa-SHA384)
        /// </summary>
        ES384,
        /// <summary>
        /// The ES512 (Asymmetric) - Elliptic Curve Digital Signature Algorithm (ECDsa-SHA512)
        /// </summary>
        ES512,
    }

    /// <summary>
    /// An extensions class to convert algorithm options to strings.
    /// </summary>
    public static class SecurityAlgorithmExtensions
    {
        /// <summary>
        /// Convert Algorithm to string form.
        /// </summary>
        public static string ToString(this SecurityAlgorithm alg)
        {
            return alg switch
            {
                SecurityAlgorithm.HS256 => "HS256",
                SecurityAlgorithm.HS384 => "HS384",
                SecurityAlgorithm.HS512 => "HS512",
                SecurityAlgorithm.RS256 => "RS256",
                SecurityAlgorithm.RS384 => "RS384",
                SecurityAlgorithm.RS512 => "RS512",
                SecurityAlgorithm.ES256 => "ES256",
                SecurityAlgorithm.ES384 => "ES384",
                SecurityAlgorithm.ES512 => "ES512",
                _ => "HS256",
            };
        }
    }
}
