using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Ng.JwtTokenService.RSA
{
    /// <summary>
    /// A Helper for RSA security keys
    /// </summary>
    public sealed class RsaHelper : IDisposable
    {
        private readonly HashSet<RSACng> rsaCngList = [];

        /// <summary>
        /// Creates the RSA security key.
        /// </summary>
        /// <param name="keySize">Size of the key in bits.</param>
        /// <param name="cngKeyCreationParameters">The optional CNG key creation parameters. If not provided, defaults will be used.</param>
        /// <returns>RsaSecurityKey</returns>
        public RsaSecurityKey CreateRSASecurityKey(int keySize = 2048, CngKeyCreationParameters? cngKeyCreationParameters = null)
        {
            cngKeyCreationParameters ??= new CngKeyCreationParameters
            {
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                KeyUsage = CngKeyUsages.AllUsages,
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
            };
            cngKeyCreationParameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(keySize), CngPropertyOptions.None)); //Define RSA keySize
            using var cngKey = CngKey.Create(CngAlgorithm.Rsa, null, cngKeyCreationParameters);
            var rsaCng = new RSACng(cngKey);
            rsaCngList.Add(rsaCng);
            return new RsaSecurityKey(rsaCng);
        }

        /// <summary>
        /// RSASecurityKey to private key string.
        /// </summary>
        /// <param name="rsaSecurityKey">The RSA security key.</param>
        /// <param name="format">The private key format.</param>
        /// <param name="passwordBytes">The password bytes. Only used for Encrypted PKCS8 format. It will encrypt the PKCS8 private key with a user defined password.</param>
        /// <param name="pbeParameters">The pbe parameters. Only used for Encrypted PKCS8 format.</param>
        /// <returns>A base64 encoded private key</returns>
        public static string RsaSecurityKeyToPrivateKeyString(RsaSecurityKey rsaSecurityKey, PrivateKeyFormat format = PrivateKeyFormat.PKCS8, byte[]? passwordBytes = null, PbeParameters? pbeParameters = null)
        {
            var rsaCng = (rsaSecurityKey?.Rsa as RSACng) ?? throw new ArgumentNullException(nameof(rsaSecurityKey));
            var bytes = format switch
            {
                PrivateKeyFormat.PKCS1 => rsaCng.ExportRSAPrivateKey(),
                PrivateKeyFormat.PKCS8 => rsaCng.ExportPkcs8PrivateKey(),
                PrivateKeyFormat.PKCS8Encrypted => rsaCng.ExportEncryptedPkcs8PrivateKey(passwordBytes, pbeParameters ?? throw new ArgumentNullException(nameof(pbeParameters))),
                _ => rsaCng.ExportPkcs8PrivateKey(),
            };
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// RSASecurityKey to public key string.
        /// </summary>
        /// <param name="rsaSecurityKey">The RSA security key.</param>
        /// <param name="format">The format.</param>
        /// <returns>A base64 encoded public key</returns>
        public static string RsaSecurityKeyToPublicKeyString(RsaSecurityKey rsaSecurityKey, PublicKeyFormat format = PublicKeyFormat.X509)
        {
            var rsaCng = (rsaSecurityKey?.Rsa as RSACng) ?? throw new ArgumentNullException(nameof(rsaSecurityKey));
            var bytes = format switch
            {
                PublicKeyFormat.PKCS1 => rsaCng.ExportRSAPublicKey(),
                PublicKeyFormat.X509 => rsaCng.ExportSubjectPublicKeyInfo(),
                _ => rsaCng.ExportSubjectPublicKeyInfo(),
            };
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Private key string to RsaSecurityKey.
        /// </summary>
        /// <param name="privateKeyString">The private key string.</param>
        /// <param name="format">The private key format.</param>
        /// <param name="passwordBytes">The password bytes. Only needed for encrypted PKCS8 format.</param>
        /// <returns>RsaSecurityKey</returns>
        public RsaSecurityKey PrivateKeyStringToRsaSecurityKey(string privateKeyString, PrivateKeyFormat format = PrivateKeyFormat.PKCS8, byte[]? passwordBytes = null)
        {
            var rsaCng = new RSACng();
            rsaCngList.Add(rsaCng);
            var bytes = Convert.FromBase64String(privateKeyString);
            switch (format)
            {
                case PrivateKeyFormat.PKCS1:
                    rsaCng.ImportRSAPrivateKey(bytes, out _);
                    break;
                case PrivateKeyFormat.PKCS8:
                    rsaCng.ImportPkcs8PrivateKey(bytes, out _);
                    break;
                case PrivateKeyFormat.PKCS8Encrypted:
                    rsaCng.ImportEncryptedPkcs8PrivateKey(passwordBytes, bytes, out _);
                    break;
                default:
                    rsaCng.ImportPkcs8PrivateKey(bytes, out _);
                    break;
            }
            return new RsaSecurityKey(rsaCng);
        }

        /// <summary>
        /// Public key string to RsaSecurityKey.
        /// </summary>
        /// <param name="publicKeyString">The public key string.</param>
        /// <param name="format">The public key format.</param>
        /// <returns>RsaSecurityKey</returns>
        public RsaSecurityKey PublicKeyStringToRsaSecurityKey(string publicKeyString, PublicKeyFormat format = PublicKeyFormat.X509)
        {
            var rsaCng = new RSACng();
            rsaCngList.Add(rsaCng);
            var bytes = Convert.FromBase64String(publicKeyString);
            switch (format)
            {
                case PublicKeyFormat.PKCS1:
                    rsaCng.ImportRSAPublicKey(bytes, out _);
                    break;
                case PublicKeyFormat.X509:
                    rsaCng.ImportSubjectPublicKeyInfo(bytes, out _);
                    break;
                default:
                    rsaCng.ImportSubjectPublicKeyInfo(bytes, out _);
                    break;
            }
            return new RsaSecurityKey(rsaCng);
        }

        /// <summary>
        /// This will dispose of all key material that was used to generate keys. If key material is disposed, all generated keys will also not work anymore.
        /// Only dispose if you don't need the generated keys anymore.
        /// </summary>
        public void Dispose()
        {
            foreach (var item in rsaCngList)
            {
                item.Dispose();
            }
        }
    }
}
