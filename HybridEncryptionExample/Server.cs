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
            byte[] aesKey = Helper.RsaDecrypt(RsaParameters, rsaEncryptedAesSecret);
            string message = Helper.AesDecrypt(aesKey, aesIv, aesEncryptedMessage);

            Console.WriteLine(message);
        }
    }
}
