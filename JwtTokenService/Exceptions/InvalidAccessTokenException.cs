using System;
using System.Runtime.Serialization;

namespace Ng.JwtTokenService.Exceptions
{
    /// <summary>
    /// The Access token is invalid exception
    /// </summary>
    [Serializable]
    public class InvalidAccessTokenException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidAccessTokenException"/> class.
        /// </summary>
        public InvalidAccessTokenException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidAccessTokenException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public InvalidAccessTokenException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidAccessTokenException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (<see langword="Nothing" /> in Visual Basic) if no inner exception is specified.</param>
        public InvalidAccessTokenException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidAccessTokenException"/> class.
        /// </summary>
        protected InvalidAccessTokenException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}