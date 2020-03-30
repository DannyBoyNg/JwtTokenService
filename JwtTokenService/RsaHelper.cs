using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace DannyBoyNg.Services
{
    public static class RsaHelper
    {
        public static RsaSecurityKey CreateRSASecurityKey(int keySize = 2048, CngKeyCreationParameters? cngKeyCreationParameters = null)
        {
            if (cngKeyCreationParameters == null) cngKeyCreationParameters = new CngKeyCreationParameters
            {
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                KeyUsage = CngKeyUsages.AllUsages,
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
            };
            cngKeyCreationParameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(keySize), CngPropertyOptions.None)); //Define RSA keySize
            using var cngKey = CngKey.Create(CngAlgorithm.Rsa, null, cngKeyCreationParameters);
            var rsaCng = new RSACng(cngKey);
            return new RsaSecurityKey(rsaCng);
        }

        public static string RsaSecurityKeyToPrivateKeyString(RsaSecurityKey rsaSecurityKey, PrivateKeyFormat format = PrivateKeyFormat.PKCS8, byte[]? passwordBytes = null, PbeParameters? pbeParameters = null)
        {
            var rsaCng = (rsaSecurityKey?.Rsa as RSACng) ?? throw new NullReferenceException();
            var bytes = format switch
            {
                PrivateKeyFormat.PKCS1 => rsaCng.ExportRSAPrivateKey(),
                PrivateKeyFormat.PKCS8 => rsaCng.ExportPkcs8PrivateKey(),
                PrivateKeyFormat.PKCS8Encrypted => rsaCng.ExportEncryptedPkcs8PrivateKey(passwordBytes, pbeParameters),
                _ => rsaCng.ExportPkcs8PrivateKey(),
            };
            return Convert.ToBase64String(bytes);
        }

        public static string RsaSecurityKeyToPublicKeyString(RsaSecurityKey rsaSecurityKey, PublicKeyFormat format = PublicKeyFormat.X509)
        {
            var rsaCng = (rsaSecurityKey?.Rsa as RSACng) ?? throw new NullReferenceException();
            var bytes = format switch
            {
                PublicKeyFormat.PKCS1 => rsaCng.ExportRSAPublicKey(),
                PublicKeyFormat.X509 => rsaCng.ExportSubjectPublicKeyInfo(),
                _ => rsaCng.ExportSubjectPublicKeyInfo(),
            };
            return Convert.ToBase64String(bytes);
        }

        public static RsaSecurityKey PrivateKeyStringToRsaSecurityKey(string privateKeyString, PrivateKeyFormat format = PrivateKeyFormat.PKCS8, byte[]? passwordBytes = null)
        {
            var rsaCng = new RSACng();
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

        public static RsaSecurityKey PublicKeyStringToRsaSecurityKey(string publicKeyString, PublicKeyFormat format = PublicKeyFormat.X509)
        {
            var rsaCng = new RSACng();
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
    }
}
