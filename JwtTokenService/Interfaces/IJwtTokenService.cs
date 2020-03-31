﻿using System.Collections.Generic;
using System.Security.Claims;

namespace DannyBoyNg.Services
{
    /// <summary>
    /// The default JWT token service interface
    /// </summary>
    public interface IJwtTokenService
    {
        /// <summary>
        /// Gets the refresh token repo if set.
        /// </summary>
        IRefreshTokenRepository? RefreshTokenRepo { get; }
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
        /// Generates an access token from an old access token.
        /// </summary>
        /// <param name="oldAccessToken">The old access token.</param>
        /// <returns>A new access token</returns>
        string GenerateAccessTokenFromOldAccessToken(string oldAccessToken);
        /// <summary>
        /// Generates a refresh token.
        /// </summary>
        /// <returns>Refresh token</returns>
        string GenerateRefreshToken();
        /// <summary>
        /// Gets all the claims that are contained in the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        List<Claim> GetAllClaims(ClaimsPrincipal claimsPrincipal);
        /// <summary>
        /// Gets a specific claim from the access token.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        /// <param name="claimType">The specific type of claim.</param>
        /// <returns>The value of the claim</returns>
        string? GetClaim(ClaimsPrincipal claimsPrincipal, string claimType);
        /// <summary>
        /// Validate the access token and get the claims principal from access token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The claims principal contained in the access token.</returns>
        ClaimsPrincipal GetPrincipalFromAccessToken(string accessToken);
        /// <summary>
        /// Validate the access token and get the claims principal from an expired access token. This method will not check the expiration time on the token.
        /// </summary>
        /// <param name="accessToken">The access token.</param>
        /// <returns>The claims principal contained in the access token</returns>
        ClaimsPrincipal GetPrincipalFromExpiredAccessToken(string accessToken);
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
        List<Claim> GetUserDefinedClaims(ClaimsPrincipal claimsPrincipal);
        /// <summary>
        /// Gets the username.
        /// </summary>
        /// <param name="claimsPrincipal">The claims principal.</param>
        string? GetUserName(ClaimsPrincipal claimsPrincipal);
        /// <summary>
        /// Stores the refresh token with the provided repository that implements IRefreshTokenRepository.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="refreshToken">The refresh token.</param>
        void StoreRefreshToken(int userId, string refreshToken);
        /// <summary>
        /// Validates the refresh token. This method will also need a repository that implements IRefreshTokenRepository.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="refreshToken">The refresh token.</param>
        void ValidateRefreshToken(int userId, string refreshToken);
    }
}