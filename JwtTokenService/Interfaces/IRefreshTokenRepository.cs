using System.Collections.Generic;

namespace DannyBoyNg.Services
{
    public interface IRefreshTokenRepository
    {
        void Insert(int userId, string refreshToken);
        void Delete(IRefreshToken refreshToken);
        void DeleteAll(int userId);
        IEnumerable<IRefreshToken> GetByUserId(int userId);
    }
}