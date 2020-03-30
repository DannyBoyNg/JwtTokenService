using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace DannyBoyNg.Services
{
    public static class ECDsaHelper
    {
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

        public static string ECDsaSecurityKeyToPrivateKeyString(ECDsaSecurityKey ecdsaSecurityKey)
        {
            var ecdsaCng = (ecdsaSecurityKey?.ECDsa as ECDsaCng) ?? throw new NullReferenceException();
            return Convert.ToBase64String(ecdsaCng.ExportPkcs8PrivateKey());
        }

        public static string ECDsaSecurityKeyToPublicKeyString(ECDsaSecurityKey ecdsaSecurityKey)
        {
            var ecdsaCng = (ecdsaSecurityKey?.ECDsa as ECDsaCng) ?? throw new NullReferenceException();
            return Convert.ToBase64String(ecdsaCng.ExportSubjectPublicKeyInfo());
        }

        public static ECDsaSecurityKey PrivateKeyStringToECDsaSecurityKey(string privateKeyString)
        {
            var ecdsaCng = new ECDsaCng();
            ecdsaCng.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyString), out _);
            return new ECDsaSecurityKey(ecdsaCng);
        }

        public static ECDsaSecurityKey PublicKeyStringToECDsaSecurityKey(string publicKeyString)
        {
            var ecdsaCng = new ECDsaCng();
            ecdsaCng.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeyString), out _);
            return new ECDsaSecurityKey(ecdsaCng);
        }
    }
}
