using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace HybridEncryptionExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var server = new Server();
            var client = new Client();

            client.SendMessage(server, "This is a super secret message!");

            Console.ReadKey();
        }
    }

    class Client
    {
        public byte[] Secret { get; set; }

        public Client()
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.GenerateKey();

                Secret = aes.Key;
            }
        }

        public void SendMessage(Server server, string message)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = Secret;
                aes.GenerateIV();

                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(server.PublicParameters);

                    server.ReceiveHybridMessage(rsa.Encrypt(Secret, false),
                        aes.IV,
                        Helper.AesEncrypt(Secret, aes.IV, message));
                }
            }
        }
    }

    class Server
    {
        private RSAParameters RsaParameters { get; set; }
        public RSAParameters PublicParameters { get; private set; }

        public Server()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                PublicParameters = rsa.ExportParameters(false);
                RsaParameters = rsa.ExportParameters(true);
            }
        }

        public void ReceiveHybridMessage(byte[] rsaEncryptedAesSecret, byte[] aesIv, byte[] aesEncryptedMessage)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(RsaParameters);

                Console.WriteLine(Helper.AesDecrypt(rsa.Decrypt(rsaEncryptedAesSecret, false), aesIv, aesEncryptedMessage));
            }
        }
    }

    class Helper
    {
        public static byte[] AesEncrypt(byte[] key, byte[] iv, string message)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    using (var sw = new StreamWriter(cs))
                    {
                        sw.Write(message);
                    }

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

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                using (var ms = new MemoryStream(message))
                using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (var sr = new StreamReader(cs, Encoding.UTF8))
                    return sr.ReadToEnd();
            }
        }
    }
}
