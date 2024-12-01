using System;
using System.Runtime.Serialization;

namespace Ng.JwtTokenService.Exceptions
{
    /// <summary>
    /// Encryption key was not set Exception
    /// </summary>
    [Serializable]
    public class EncryptionKeyNotSetException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyNotSetException"/> class.
        /// </summary>
        public EncryptionKeyNotSetException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyNotSetException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public EncryptionKeyNotSetException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyNotSetException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (<see langword="Nothing" /> in Visual Basic) if no inner exception is specified.</param>
        public EncryptionKeyNotSetException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyNotSetException"/> class.
        /// </summary>
        protected EncryptionKeyNotSetException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}