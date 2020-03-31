using System;
using System.Runtime.Serialization;

namespace DannyBoyNg.Services
{
    /// <summary>
    /// The refresh token is invalid exception
    /// </summary>
    [Serializable]
    public class InvalidRefreshTokenException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidRefreshTokenException"/> class.
        /// </summary>
        public InvalidRefreshTokenException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidRefreshTokenException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public InvalidRefreshTokenException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidRefreshTokenException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (<see langword="Nothing" /> in Visual Basic) if no inner exception is specified.</param>
        public InvalidRefreshTokenException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidRefreshTokenException"/> class.
        /// </summary>
        protected InvalidRefreshTokenException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}