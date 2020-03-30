using System;
using System.Runtime.Serialization;

namespace DannyBoyNg.Services
{
    [Serializable]
    public class NoRefreshTokenRepositorySetException : Exception
    {
        public NoRefreshTokenRepositorySetException()
        {
        }

        public NoRefreshTokenRepositorySetException(string message) : base(message)
        {
        }

        public NoRefreshTokenRepositorySetException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected NoRefreshTokenRepositorySetException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}