using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace DannyBoyNg.Services
{
    /// <summary>
    /// A Helper for ECDsa security keys
    /// </summary>
    public static class ECDsaHelper
    {
        /// <summary>
        /// Creates an Elliptic Curve DSA security key.
        /// </summary>
        /// <param name="curve">An optional Curve Type.</param>
        /// <param name="cngKeyCreationParameters">The CNG key creation parameters.</param>
        /// <returns>ECDsaSecurityKey</returns>
        public static ECDsaSecurityKey CreateECDsaSecurityKey(ECDsaCurve curve = ECDsaCurve.P256, CngKeyCreationParameters? cngKeyCreationParameters = null)
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
            ECDsa ecdsaCng = new ECDsaCng(cngKey);
            return new ECDsaSecurityKey(ecdsaCng);
        }

        /// <summary>
        /// ECDsaSecurityKey to private key string (base64 encoded).
        /// </summary>
        /// <returns>string</returns>
        /// <exception cref="NullReferenceException">Thrown when ecdsaSecurityKey is null or ecdsaSecurityKey.ECDsa is null</exception>
        public static string ECDsaSecurityKeyToPrivateKeyString(ECDsaSecurityKey ecdsaSecurityKey)
        {
            var ecdsaCng = (ecdsaSecurityKey?.ECDsa as ECDsaCng) ?? throw new NullReferenceException();
            return Convert.ToBase64String(ecdsaCng.ExportPkcs8PrivateKey());
        }

        /// <summary>
        /// ECDsaSecurityKey to public key string (base64 encoded).
        /// </summary>
        /// <param name="ecdsaSecurityKey">The ecdsa security key.</param>
        /// <returns></returns>
        /// <exception cref="NullReferenceException"></exception>
        public static string ECDsaSecurityKeyToPublicKeyString(ECDsaSecurityKey ecdsaSecurityKey)
        {
            var ecdsaCng = (ecdsaSecurityKey?.ECDsa as ECDsaCng) ?? throw new NullReferenceException();
            return Convert.ToBase64String(ecdsaCng.ExportSubjectPublicKeyInfo());
        }

        /// <summary>
        /// Private key string to ECDsaSecurityKey.
        /// </summary>
        /// <param name="privateKeyString">The private key string (base64 encoded).</param>
        /// <returns>ECDsaSecurityKey</returns>
        public static ECDsaSecurityKey PrivateKeyStringToECDsaSecurityKey(string privateKeyString)
        {
            var ecdsaCng = new ECDsaCng();
            ecdsaCng.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyString), out _);
            return new ECDsaSecurityKey(ecdsaCng);
        }

        /// <summary>
        /// Public key string to ECDsaSecurityKey.
        /// </summary>
        /// <param name="publicKeyString">The public key string (base64 encoded).</param>
        /// <returns>ECDsaSecurityKey</returns>
        public static ECDsaSecurityKey PublicKeyStringToECDsaSecurityKey(string publicKeyString)
        {
            var ecdsaCng = new ECDsaCng();
            ecdsaCng.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyString), out _);
            return new ECDsaSecurityKey(ecdsaCng);
        }
    }
}
