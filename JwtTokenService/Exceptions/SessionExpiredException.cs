using System;
using System.Runtime.Serialization;

namespace Ng.JwtTokenService.Exceptions
{
    /// <summary>
    /// Session expired Exception. Also refers too the refresh token being expired.
    /// </summary>
    [Serializable]
    public class SessionExpiredException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SessionExpiredException"/> class.
        /// </summary>
        public SessionExpiredException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionExpiredException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public SessionExpiredException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionExpiredException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (<see langword="Nothing" /> in Visual Basic) if no inner exception is specified.</param>
        public SessionExpiredException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SessionExpiredException"/> class.
        /// </summary>
        protected SessionExpiredException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}