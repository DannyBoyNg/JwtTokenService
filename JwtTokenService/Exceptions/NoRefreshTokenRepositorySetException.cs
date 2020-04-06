using System;
using System.Runtime.Serialization;

namespace Ng.Services
{
    /// <summary>
    /// No refresh token repository was provided Exception
    /// </summary>
    [Serializable]
    public class NoRefreshTokenRepositorySetException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NoRefreshTokenRepositorySetException"/> class.
        /// </summary>
        public NoRefreshTokenRepositorySetException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NoRefreshTokenRepositorySetException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public NoRefreshTokenRepositorySetException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NoRefreshTokenRepositorySetException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (<see langword="Nothing" /> in Visual Basic) if no inner exception is specified.</param>
        public NoRefreshTokenRepositorySetException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="NoRefreshTokenRepositorySetException"/> class.
        /// </summary>
        protected NoRefreshTokenRepositorySetException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}