using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace DannyBoyNg.Services
{
    public class JwtTokenService : IJwtTokenService
    {
        public JwtTokenSettings Settings { get; }
        public IRefreshTokenRepository? RefreshTokenRepo { get; } = null;

        public JwtTokenService(JwtTokenSettings settings) => Settings = settings ?? new JwtTokenSettings();

        public JwtTokenService(
            IOptions<JwtTokenSettings> settings,
            IRefreshTokenRepository? refreshTokenRepo = null)
        {
            Settings = settings?.Value ?? new JwtTokenSettings();
            RefreshTokenRepo = refreshTokenRepo;
        }

        public JwtTokenService(
            JwtTokenSettings settings,
            IRefreshTokenRepository? refreshTokenRepo = null)
        {
            Settings = settings ?? new JwtTokenSettings();
            RefreshTokenRepo = refreshTokenRepo;
        }

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

        public string GenerateAccessTokenFromOldAccessToken(string oldAccessToken)
        {
            var claimsPrincipal = GetPrincipalFromExpiredAccessToken(oldAccessToken);
            var userNameFromToken = GetUserName(claimsPrincipal) ?? throw new NullReferenceException();
            var roles = GetRoles(claimsPrincipal);
            var userDefinedClaims = GetUserDefinedClaims(claimsPrincipal);
            return GenerateAccessToken(userNameFromToken, roles, userDefinedClaims);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredAccessToken(string accessToken)
        {
            var tokenValidationParameters = Settings.TokenValidationParameters ?? throw new TokenValidationParametersNotSetException();
            tokenValidationParameters.ValidateLifetime = false;
            return ValidateAccessToken(accessToken, tokenValidationParameters);
        }

        public ClaimsPrincipal GetPrincipalFromAccessToken(string accessToken)
        {
            var tokenValidationParameters = Settings.TokenValidationParameters ?? throw new TokenValidationParametersNotSetException();
            return ValidateAccessToken(accessToken, tokenValidationParameters);
        }

        private ClaimsPrincipal ValidateAccessToken(string accessToken, TokenValidationParameters tokenValidationParameters)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claimsPrincipal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);
            if (!(securityToken is JwtSecurityToken jwtSecurityToken) || !jwtSecurityToken.Header.Alg.Equals(Settings.SecurityAlgorithm.ToString(), StringComparison.InvariantCultureIgnoreCase))
            {
                throw new InvalidAccessTokenException();
            }
            return claimsPrincipal;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "In favor of a more consistent api over performance")]
        public List<Claim> GetAllClaims(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null) return new List<Claim>();
            return claimsPrincipal.Claims.ToList();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "In favor of a more consistent api over performance")]
        public List<Claim> GetUserDefinedClaims(ClaimsPrincipal claimsPrincipal)
        {
            if (claimsPrincipal == null) return new List<Claim>();
            return claimsPrincipal.Claims.Where(UserDefinedClaimsFilter).ToList();
        }

        public string? GetClaim(ClaimsPrincipal claimsPrincipal, string claimType)
        {
            return claimsPrincipal?.Claims?.FirstOrDefault(x => x.Type == claimType)?.Value;
        }

        public string? GetUserName(ClaimsPrincipal claimsPrincipal)
        {
            return GetClaim(claimsPrincipal, ClaimTypes.Name);
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "In favor of a more consistent api over performance")]
        public string[]? GetRoles(ClaimsPrincipal claimsPrincipal)
        {
            return claimsPrincipal?.Claims?.Where(x => x.Type == ClaimTypes.Role).Select(x => x.Value).ToArray();
        }

        public string GenerateRefreshToken()
        {
            byte[] time = BitConverter.GetBytes(DateTime.UtcNow.ToBinary());
            byte[] key = Guid.NewGuid().ToByteArray();
            return Convert.ToBase64String(time.Concat(key).ToArray()).Replace('/', '_').Replace('+', '-');
        }

        public void StoreRefreshToken(int userId, string refreshToken)
        {
            if (RefreshTokenRepo == null) throw new NoRefreshTokenRepositorySetException();
            if (refreshToken == null) throw new ArgumentNullException(nameof(refreshToken));
            RefreshTokenRepo.Insert(userId, refreshToken);
        }

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
