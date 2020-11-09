using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace Ng.Services
{
    /// <summary>
    /// A Helper for ECDsa security keys
    /// </summary>
    public sealed class ECDsaHelper : IDisposable
    {
        ECDsa? ecdsaCng;

        /// <summary>
        /// Creates an Elliptic Curve DSA security key.
        /// </summary>
        /// <param name="curve">An optional Curve Type.</param>
        /// <param name="cngKeyCreationParameters">The CNG key creation parameters.</param>
        /// <returns>ECDsaSecurityKey</returns>
        public ECDsaSecurityKey CreateECDsaSecurityKey(ECDsaCurve curve = ECDsaCurve.P256, CngKeyCreationParameters? cngKeyCreationParameters = null)
        {
            if (cngKeyCreationParameters == null) cngKeyCreationParameters = new CngKeyCreationParameters
            {
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                KeyUsage = CngKeyUsages.AllUsages,
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
            };
            var algorithm = curve switch
            {
                ECDsaCurve.P256 => CngAlgorithm.ECDsaP256,
                ECDsaCurve.P384 => CngAlgorithm.ECDsaP384,
                ECDsaCurve.P521 => CngAlgorithm.ECDsaP521,
                _ => CngAlgorithm.ECDsaP256,
            };
            using CngKey cngKey = CngKey.Create(algorithm, null, cngKeyCreationParameters);
            if (ecdsaCng != null) ecdsaCng.Dispose();
            ecdsaCng = new ECDsaCng(cngKey);
            return new ECDsaSecurityKey(ecdsaCng);
        }

        /// <summary>
        /// ECDsaSecurityKey to private key string (base64 encoded).
        /// </summary>
        /// <returns>string</returns>
        /// <exception cref="NullReferenceException">Thrown when ecdsaSecurityKey is null or ecdsaSecurityKey.ECDsa is null</exception>
        public string ECDsaSecurityKeyToPrivateKeyString(ECDsaSecurityKey ecdsaSecurityKey)
        {
            ecdsaCng = (ecdsaSecurityKey?.ECDsa as ECDsaCng) ?? throw new ArgumentNullException(nameof(ecdsaSecurityKey));
            return Convert.ToBase64String(ecdsaCng.ExportPkcs8PrivateKey());
        }

        /// <summary>
        /// ECDsaSecurityKey to public key string (base64 encoded).
        /// </summary>
        /// <param name="ecdsaSecurityKey">The ecdsa security key.</param>
        /// <returns></returns>
        /// <exception cref="NullReferenceException"></exception>
        public string ECDsaSecurityKeyToPublicKeyString(ECDsaSecurityKey ecdsaSecurityKey)
        {
            ecdsaCng = (ecdsaSecurityKey?.ECDsa as ECDsaCng) ?? throw new ArgumentNullException(nameof(ecdsaSecurityKey));
            return Convert.ToBase64String(ecdsaCng.ExportSubjectPublicKeyInfo());
        }

        /// <summary>
        /// Private key string to ECDsaSecurityKey.
        /// </summary>
        /// <param name="privateKeyString">The private key string (base64 encoded).</param>
        /// <returns>ECDsaSecurityKey</returns>
        public ECDsaSecurityKey PrivateKeyStringToECDsaSecurityKey(string privateKeyString)
        {
            ecdsaCng = new ECDsaCng();
            ecdsaCng.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyString), out _);
            return new ECDsaSecurityKey(ecdsaCng);
        }

        /// <summary>
        /// Public key string to ECDsaSecurityKey.
        /// </summary>
        /// <param name="publicKeyString">The public key string (base64 encoded).</param>
        /// <returns>ECDsaSecurityKey</returns>
        public ECDsaSecurityKey PublicKeyStringToECDsaSecurityKey(string publicKeyString)
        {
            ecdsaCng = new ECDsaCng();
            ecdsaCng.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyString), out _);
            return new ECDsaSecurityKey(ecdsaCng);
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            ecdsaCng?.Dispose();
        }
    }
}
