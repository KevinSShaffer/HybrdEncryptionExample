using System;
using System.Security.Cryptography;

namespace HybridEncryptionExample
{
    public class Server
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
}
