using System;
using System.Runtime.Serialization;

namespace DannyBoyNg.Services
{
    [Serializable]
    public class EncryptionKeyNotSetException : Exception
    {
        public EncryptionKeyNotSetException()
        {
        }

        public EncryptionKeyNotSetException(string message) : base(message)
        {
        }

        public EncryptionKeyNotSetException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected EncryptionKeyNotSetException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}