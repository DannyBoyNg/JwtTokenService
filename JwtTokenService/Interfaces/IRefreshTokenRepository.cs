using System.Collections.Generic;

namespace DannyBoyNg.Services
{
    /// <summary>
    /// Default interface for refresh token repository
    /// </summary>
    public interface IRefreshTokenRepository
    {
        /// <summary>
        /// Inserts the refresh token into a data store for the specified user.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        /// <param name="refreshToken">The refresh token.</param>
        void Insert(int userId, string refreshToken);
        /// <summary>
        /// Deletes the refresh token from the data store.
        /// </summary>
        /// <param name="refreshToken">The refresh token.</param>
        void Delete(IRefreshToken refreshToken);
        /// <summary>
        /// Deletes refreshtoken associated with the specified user.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        void DeleteAll(int userId);
        /// <summary>
        /// Gets all the refresh tokens associated with the specified user.
        /// </summary>
        /// <param name="userId">The user identifier.</param>
        IEnumerable<IRefreshToken> GetByUserId(int userId);
    }
}