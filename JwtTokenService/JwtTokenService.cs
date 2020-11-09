using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace Ng.Services
{
    /// <summary>
    /// The JWT Token Service
    /// </summary>
    /// <seealso cref="Ng.Services.IJwtTokenService" />
    public class JwtTokenService : IJwtTokenService
    {
        /// <summary>
        /// Gets the settings.
        /// </summary>
        public JwtTokenSettings Settings { get; }
        /// <summary>
        /// Gets the refresh token repo if set.
        /// </summary>
        public IRefreshTokenRepository? RefreshTokenRepo { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtTokenService"/> class.
        /// </summary>
        /// <param name="settings">The JWT token settings.</param>
        public JwtTokenService(JwtTokenSettings settings) => Settings = settings ?? new JwtTokenSettings();

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtTokenService"/> class.
        /// </summary>
        /// <param name="settings">The settings.</param>
        /// <param name="refreshTokenRepo">The refresh token repo.</param>
        public JwtTokenService(
            IOptions<JwtTokenSettings> settings,
            IRefreshTokenRepository? refreshTokenRepo = null)
        {
            Settings = settings?.Value ?? new JwtTokenSettings();
            RefreshTokenRepo = refreshTokenRepo;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="JwtTokenService"/> class.
        /// </summary>
        /// <param name="settings">The JWT token settings.</param>
        /// <param name="refreshTokenRepo">The refresh token repo.</param>
        public JwtTokenService(
            JwtTokenSettings settings,
            IRefreshTokenRepository? refreshTokenRepo = null)
        {
            Settings = settings ?? new JwtTokenSettings();
            RefreshTokenRepo = refreshTokenRepo;
        }

        /// <summary>
        /// Generates an access token.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="roles">The roles associated with the user. If user has no roles, just set to null</param>
        /// <param name="userDefinedClaims">The user defined claims. All cliams you wish to out in the access token</param>
        /// <returns>
        /// An access token
        /// </returns>
        /// <exception cref="Ng.Services.EncryptionKeyNotSetException"></exception>
        /// <exception cref="Ng.Services.EncryptionKeyIsTooShortException"></exception>
        public string GenerateAccessToken(string username, IEnumerable<string>? roles = null, IEnumerable<Claim>? userDefinedClaims = null)
        {
            try
            {
                var issuedAt = DateTime.UtcNow;
                var issuedAtUnix = ((DateTimeOffset)issuedAt).ToUnixTimeSeconds();
                var expiresAt = issuedAt.AddMinutes(Settings.AccessTokenExpirationInMinutes);

                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, issuedAtUnix.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
                    new Claim(ClaimTypes.Name, username),
                };
                if (roles != null && roles.Any()) foreach (var role in roles) claims.Add(new Claim(ClaimTypes.Role, role));
                if (userDefinedClaims != null && userDefinedClaims.Any()) claims.AddRange(userDefinedClaims.Where(UserDefinedClaimsFilter));

                var key = Settings.TokenValidationParameters?.IssuerSigningKey ?? throw new EncryptionKeyNotSetException();
                var token = new JwtSecurityToken(
                  issuer: Settings.TokenValidationParameters.ValidIssuer,
                  audience: Settings.TokenValidationParameters.ValidAudience,
                  claims: claims,
                  notBefore: issuedAt,
                  expires: expiresAt,
                  signingCredentials: new SigningCredentials(key, Settings.SecurityAlgorithm.ToString())
                );
                var accessToken = new JwtSecurityTokenHandler().WriteToken(token);
                return accessToken;
            }
            catch (ArgumentOutOfRangeException) { throw new EncryptionKeyIsTooShortException(); }
        }

        /// <summary>
        /// Generates an access token from an old access token.
        /// </summary>
        /// <param name="oldAccessToken">The old access token.</param>
        /// <returns>
        /// A new access token
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown when oldAccessToken is null or an empty string.</exception>
        /// <exception cref="InvalidAccessTokenException">Thrown when it cannot retrieve username from the old access token.</exception>
        public string GenerateAccessTokenFromOldAccessToken(string oldAccessToken)
        {
            if (string.IsNullOrWhiteSpace(oldAccessToken)) throw new ArgumentNullException(nameof(oldAccessToken));
            var claimsPrincipal = GetClaimsFromExpiredAccessToken(oldAccessToken);
            var userNameFromToken = GetUserName(claimsPrincipal) ?? throw new InvalidAccessTokenException();
            var roles = GetRoles(claimsPrincipal);
            var userDefinedClaims = GetUserDefinedClaims(claimsPrincipal);
            return GenerateAccessToken(userNameFromToken, roles, userDefinedClaims);
        }

        /// <summary>
        /// Validate the access token and get the claims principal from an expired access token. This method will not check the expiration time on the token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>
        /// The claims principal contained in the access token
        /// </returns>
        /// <exception cref="Ng.Services.TokenValidationParametersNotSetException">Thrown when no TokenValidationParameters are set in the JwtTokenSettings.</exception>
        /// <exception cref="Ng.Services.InvalidAccessTokenException">Thrown when the access token does not pass validation.</exception>
        public ClaimsPrincipal GetClaimsFromExpiredAccessToken(string accessToken)
        {
            var tokenValidationParameters = Settings.TokenValidationParameters ?? throw new TokenValidationParametersNotSetException();
            tokenValidationParameters.ValidateLifetime = false;
            return ValidateAccessToken(accessToken, tokenValidationParameters);
        }

        /// <summary>
        /// Validate the access token and get the claims principal from access token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>
        /// The claims principal contained in the access token.
        /// </returns>
        /// <exception cref="Ng.Services.TokenValidationParametersNotSetException">Thrown when no TokenValidationParameters are set in the JwtTokenSettings.</exception>
        /// <exception cref="Ng.Services.InvalidAccessTokenException">Thrown when the access token does not pass validation.</exception>
        public ClaimsPrincipal GetClaimsFromAccessToken(string accessToken)
        {
            var tokenValidationParameters = Settings.TokenValidationParameters ?? throw new TokenValidationParametersNotSetException();
            return ValidateAccessToken(accessToken, tokenValidationParameters);
        }

        private ClaimsPrincipal ValidateAccessToken(string accessToken, TokenValidationParameters tokenValidationParameters)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claimsPrincipal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);
            if (!(securityToken is JwtSecurityToken jwtSecurityToken) || !jwtSecurityToken.Header.Alg.Equals(Settings.SecurityAlgorithm.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidAccessTokenException();
            }
            return claimsPrincipal;
        }

        /// <summary>
        /// Gets all the claims that are contained in the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "In favor of a more consistent api over performance")]
        public IEnumerable<Claim> GetAllClaims(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null) return new List<Claim>();
            return claimsPrincipal.Claims.ToList();
        }

        /// <summary>
        /// Gets the user defined claims.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <returns>
        /// It will only return the claims, the user has put into the access token. It will not return roles or username claims.
        /// </returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "In favor of a more consistent api over performance")]
        public IEnumerable<Claim> GetUserDefinedClaims(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null) return new List<Claim>();
            return claimsPrincipal.Claims.Where(UserDefinedClaimsFilter).ToList();
        }

        /// <summary>
        /// Gets a specific claim from the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <param name="claimType">The specific type of claim.</param>
        /// <returns>
        /// The value of the claim
        /// </returns>
        public string? GetClaim(ClaimsPrincipal claimsPrincipal, string claimType)
        {
            return claimsPrincipal?.Claims?.FirstOrDefault(x => x.Type == claimType)?.Value;
        }

        /// <summary>
        /// Gets the username.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <returns></returns>
        public string? GetUserName(ClaimsPrincipal claimsPrincipal)
        {
            return GetClaim(claimsPrincipal, ClaimTypes.Name);
        }

        /// <summary>
        /// Gets the authorization roles containes in the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <returns>
        /// A list of roles associated with the user.
        /// </returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "In favor of a more consistent api over performance")]
        public string[]? GetRoles(ClaimsPrincipal claimsPrincipal)
        {
            return claimsPrincipal?.Claims?.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToArray();
        }

        /// <summary>
        /// Generates a refresh token.
        /// </summary>
        /// <returns>
        /// Refresh token
        /// </returns>
        public string GenerateRefreshToken()
        {
            byte[] time = BitConverter.GetBytes(DateTime.UtcNow.ToBinary());
            byte[] key = Guid.NewGuid().ToByteArray();
            return Convert.ToBase64String(time.Concat(key).ToArray()).Replace('/', '_').Replace('+', '-');
        }

        /// <summary>
        /// Stores the refresh token with the provided repository that implements IRefreshTokenRepository.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <exception cref="Ng.Services.NoRefreshTokenRepositorySetException">Thrown when the refresh token repository is not provided.</exception>
        /// <exception cref="ArgumentNullException">Thrown when the refresh token is null.</exception>
        public void StoreRefreshToken(int userId, string refreshToken)
        {
            if (RefreshTokenRepo == null) throw new NoRefreshTokenRepositorySetException();
            if (refreshToken == null) throw new ArgumentNullException(nameof(refreshToken));
            RefreshTokenRepo.Insert(userId, refreshToken);
        }

        /// <summary>
        /// Validates the refresh token. This method will also need a repository that implements IRefreshTokenRepository.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="refreshToken">The refresh token.</param>
        /// <exception cref="Ng.Services.NoRefreshTokenRepositorySetException">Thrown when the refresh token repository is not provided.</exception>
        /// <exception cref="Ng.Services.SessionExpiredException">Thrown when the refresh token is expired.</exception>
        /// <exception cref="Ng.Services.InvalidRefreshTokenException">Thrown when the refresh token cannot be found in the data store.</exception>
        public void ValidateRefreshToken(int userId, string refreshToken)
        {
            if (RefreshTokenRepo == null) throw new NoRefreshTokenRepositorySetException();
            var tokenExpired = false;
            var tokens = RefreshTokenRepo.GetByUserId(userId).ToList();
            //Remove expired refresh tokens from db
            foreach (var token in tokens)
            {
                if (IsRefreshTokenExpired(token.Token))
                {
                    if (token.Token == refreshToken) tokenExpired = true;
                    RefreshTokenRepo.Delete(token);
                }
            }
            //Validate user provided refresh token
            var dbToken = tokens.Where(x => x.Token == refreshToken).SingleOrDefault();
            if (dbToken != null) RefreshTokenRepo.Delete(dbToken);
            if (tokenExpired) throw new SessionExpiredException();
            if (dbToken == null) throw new InvalidRefreshTokenException();
        }

        private bool IsRefreshTokenExpired(string refreshToken)
        {
            if (Settings.RefreshTokenExpirationInHours == 0) return false; //When set to 0, refresh token never expires
            DateTime when = GetCreationTimeFromRefreshToken(refreshToken);
            return when < DateTime.UtcNow.AddHours(Settings.RefreshTokenExpirationInHours * -1);
        }

        private static DateTime GetCreationTimeFromRefreshToken(string refreshToken)
        {
            if (refreshToken == null) throw new ArgumentNullException(nameof(refreshToken));
            refreshToken = refreshToken.Replace('_', '/').Replace('-', '+');
            switch (refreshToken.Length % 4)
            {
                case 2: refreshToken += "=="; break;
                case 3: refreshToken += "="; break;
            }
            byte[] data = Convert.FromBase64String(refreshToken);
            return DateTime.FromBinary(BitConverter.ToInt64(data, 0));
        }

        private static bool UserDefinedClaimsFilter(Claim x)
        {
            return x.Type != JwtRegisteredClaimNames.Jti
            && x.Type != JwtRegisteredClaimNames.Iat
            && x.Type != JwtRegisteredClaimNames.Nbf
            && x.Type != JwtRegisteredClaimNames.Exp
            && x.Type != JwtRegisteredClaimNames.Iss
            && x.Type != JwtRegisteredClaimNames.Aud
            && x.Type != ClaimTypes.Name
            && x.Type != ClaimTypes.Role;
        }
    }
}
