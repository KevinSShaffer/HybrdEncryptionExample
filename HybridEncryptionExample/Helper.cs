using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace HybridEncryptionExample
{
    public class Helper
    {
        public static byte[] GenerateRandom(int size)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] bytes = new byte[size];

                rng.GetBytes(bytes);

                return bytes;
            }
        }

        public static byte[] RsaEncrypt(RSAParameters parameters, byte[] data)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(parameters);

                return rsa.Encrypt(data, false);
            }
        }

        public static byte[] RsaDecrypt(RSAParameters parameters, byte[] data)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(parameters);

                return rsa.Decrypt(data, false);
            }
        }

        public static byte[] AesEncrypt(byte[] key, byte[] iv, string message)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor())
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                        sw.Write(message);

                    return ms.ToArray();
                }
            }
        }

        public static string AesDecrypt(byte[] key, byte[] iv, byte[] message)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor())
                using (var ms = new MemoryStream(message))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs, Encoding.UTF8))
                    return sr.ReadToEnd();
            }
        }
    }
}
