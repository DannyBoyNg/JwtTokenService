using System;
using System.Runtime.Serialization;

namespace Ng.JwtTokenService.Exceptions
{
    /// <summary>
    /// The encryption key is too short Exception
    /// </summary>
    [Serializable]
    public class EncryptionKeyIsTooShortException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyIsTooShortException"/> class.
        /// </summary>
        public EncryptionKeyIsTooShortException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyIsTooShortException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public EncryptionKeyIsTooShortException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyIsTooShortException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception, or a null reference (<see langword="Nothing" /> in Visual Basic) if no inner exception is specified.</param>
        public EncryptionKeyIsTooShortException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionKeyIsTooShortException"/> class.
        /// </summary>
        protected EncryptionKeyIsTooShortException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}