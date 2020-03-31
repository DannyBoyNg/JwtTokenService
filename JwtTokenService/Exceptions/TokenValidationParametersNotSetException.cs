using System;
using System.Runtime.Serialization;

namespace DannyBoyNg.Services
{
    /// <summary>
    /// Token Validation Parameters were not provided exception
    /// </summary>
    [Serializable]
    public class TokenValidationParametersNotSetException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParametersNotSetException"/> class.
        /// </summary>
        public TokenValidationParametersNotSetException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParametersNotSetException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public TokenValidationParametersNotSetException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParametersNotSetException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (<see langword="Nothing" /> in Visual Basic) if no inner exception is specified.</param>
        public TokenValidationParametersNotSetException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TokenValidationParametersNotSetException"/> class.
        /// </summary>
        protected TokenValidationParametersNotSetException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}