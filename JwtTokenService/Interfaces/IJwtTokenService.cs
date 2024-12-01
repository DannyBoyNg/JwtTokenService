using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Ng.JwtTokenService.Interfaces
{
    /// <summary>
    /// The default JWT token service interface
    /// </summary>
    public interface IJwtTokenService
    {
        /// <summary>
        /// Gets the settings.
        /// </summary>
        JwtTokenSettings Settings { get; }

        /// <summary>
        /// Generates the access token.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <param name="roles">The roles.</param>
        /// <param name="userDefinedClaims">The user defined claims.</param>
        /// <returns>An access token</returns>
        string GenerateAccessToken(string username, IEnumerable<string>? roles = null, IEnumerable<Claim>? userDefinedClaims = null);
        /// <summary>
        /// [Obsolete] Generates an access token from an old access token.
        /// </summary>
        /// <param name="oldAccessToken">The old access token.</param>
        /// <returns>A new access token</returns>
        [Obsolete("This method is obsolete, please use GenerateAccessTokenFromOldAccessTokenAsync instead. This breaking change is caused by upgrading the package System.IdentityModel.Tokens.Jwt to the more modern Microsoft.IdentityModel.JsonWebTokens", true)]
        string GenerateAccessTokenFromOldAccessToken(string oldAccessToken);
        /// <summary>
        /// Generates an access token from an old access token.
        /// </summary>
        /// <param name="oldAccessToken">The old access token.</param>
        /// <returns>A new access token</returns>
        Task<string> GenerateAccessTokenFromOldAccessTokenAsync(string oldAccessToken);
        /// <summary>
        /// Generates a refresh token.
        /// </summary>
        /// <returns>Refresh token</returns>
        string GenerateRefreshToken();
        /// <summary>
        /// Gets all the claims that are contained in the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        IEnumerable<Claim> GetAllClaims(ClaimsPrincipal claimsPrincipal);
        /// <summary>
        /// Gets a specific claim from the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <param name="claimType">The specific type of claim.</param>
        /// <returns>The value of the claim</returns>
        string? GetClaim(ClaimsPrincipal claimsPrincipal, string claimType);
        /// <summary>
        /// [Obsolete] Validate the access token and get the claims principal from access token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The claims principal contained in the access token.</returns>
        [Obsolete("This method is obsolete, please use GetClaimsFromAccessTokenAsync instead. This breaking change is caused by upgrading the package System.IdentityModel.Tokens.Jwt to the more modern Microsoft.IdentityModel.JsonWebTokens", true)] 
        ClaimsPrincipal GetClaimsFromAccessToken(string accessToken);
        /// <summary>
        /// Validate the access token and get the claims principal from access token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The claims principal contained in the access token.</returns>
        Task<ClaimsPrincipal> GetClaimsFromAccessTokenAsync(string accessToken);
        /// <summary>
        /// [Obsolete] Validate the access token and get the claims principal from an expired access token. This method will not check the expiration time on the token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The claims principal contained in the access token</returns>
        [Obsolete("This method is obsolete, please use GetClaimsFromExpiredAccessTokenAsync instead. This breaking change is caused by upgrading the package System.IdentityModel.Tokens.Jwt to the more modern Microsoft.IdentityModel.JsonWebTokens", true)]
        ClaimsPrincipal GetClaimsFromExpiredAccessToken(string accessToken);
        /// <summary>
        /// Validate the access token and get the claims principal from an expired access token. This method will not check the expiration time on the token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The claims principal contained in the access token</returns>
        Task<ClaimsPrincipal> GetClaimsFromExpiredAccessTokenAsync(string accessToken);
        /// <summary>
        /// Gets the authorization roles containes in the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <returns>A list of roles associated with the user.</returns>
        string[]? GetRoles(ClaimsPrincipal claimsPrincipal);
        /// <summary>
        /// Gets the user defined claims.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <returns>It will only return the claims, the user has put into the access token. It will not return roles or username claims.</returns>
        IEnumerable<Claim> GetUserDefinedClaims(ClaimsPrincipal claimsPrincipal);
        /// <summary>
        /// Gets the username.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        string? GetUserName(ClaimsPrincipal claimsPrincipal);
        /// <summary>
        /// Check if the refresh token is expired. This does not check if the refresh token is valid. Set the token expiration in the JwtTokenSettings. To check if a refresh token is valid, you must store the refresh token in a database and then check if the refresh token belongs to the specific user.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        bool IsRefreshTokenExpired(string refreshToken);
    }
}