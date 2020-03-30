using System;
using System.Runtime.Serialization;

namespace DannyBoyNg.Services
{
    [Serializable]
    public class TokenValidationParametersNotSetException : Exception
    {
        public TokenValidationParametersNotSetException()
        {
        }

        public TokenValidationParametersNotSetException(string message) : base(message)
        {
        }

        public TokenValidationParametersNotSetException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected TokenValidationParametersNotSetException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}