using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Wcjj.Providers
{
    public static class PasswordUtil
    {
        public static string CreateRandomSalt()
        {
            var saltBytes = new Byte[4];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(saltBytes);
            return Convert.ToBase64String(saltBytes);
        }

        public static string HashPassword(string pass, string salt, string hashAlgorithm, string macKey)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(pass);
            byte[] src = Encoding.Unicode.GetBytes(salt);
            byte[] dst = new byte[src.Length + bytes.Length];
            Buffer.BlockCopy(src, 0, dst, 0, src.Length);
            Buffer.BlockCopy(bytes, 0, dst, src.Length, bytes.Length);
            HashAlgorithm algorithm;
            if (hashAlgorithm.ToUpper().Contains("HMAC"))
            {
                if (string.IsNullOrEmpty(macKey))
                    throw new ArgumentException("HMAC style hashing algorithm requires a fixed ValidationKey in the web.config or machine.config.");
                KeyedHashAlgorithm keyedAlg = KeyedHashAlgorithm.Create(hashAlgorithm);
                keyedAlg.Key = HexToByte(macKey);
                algorithm = keyedAlg;
            }
            else
            {
                algorithm = HashAlgorithm.Create(hashAlgorithm);
            }
            byte[] inArray = algorithm.ComputeHash(dst);
            return Convert.ToBase64String(inArray);
        }

        private static byte[] HexToByte(string hexString)
        {
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return returnBytes;
        }
    }
}
