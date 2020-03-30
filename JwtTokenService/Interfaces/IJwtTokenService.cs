using System.Collections.Generic;
using System.Security.Claims;

namespace DannyBoyNg.Services
{
    public interface IJwtTokenService
    {
        IRefreshTokenRepository? RefreshTokenRepo { get; }
        JwtTokenSettings Settings { get; }

        string GenerateAccessToken(string username, IEnumerable<string>? roles = null, IEnumerable<Claim>? userDefinedClaims = null);
        string GenerateAccessTokenFromOldAccessToken(string oldAccessToken);
        string GenerateRefreshToken();
        List<Claim> GetAllClaims(ClaimsPrincipal claimsPrincipal);
        string? GetClaim(ClaimsPrincipal claimsPrincipal, string claimType);
        ClaimsPrincipal GetPrincipalFromAccessToken(string accessToken);
        ClaimsPrincipal GetPrincipalFromExpiredAccessToken(string accessToken);
        string[]? GetRoles(ClaimsPrincipal claimsPrincipal);
        List<Claim> GetUserDefinedClaims(ClaimsPrincipal claimsPrincipal);
        string? GetUserName(ClaimsPrincipal claimsPrincipal);
        void StoreRefreshToken(int userId, string refreshToken);
        void ValidateRefreshToken(int userId, string refreshToken);
    }
}