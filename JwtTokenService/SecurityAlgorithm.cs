namespace DannyBoyNg.Services
{
    public enum SecurityAlgorithm
    {
        HS256,
        HS384,
        HS512,
        RS256,
        RS384,
        RS512,
        ES256,
        ES384,
        ES512,
    }

    public static class SecurityAlgorithmExtensions
    {
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
