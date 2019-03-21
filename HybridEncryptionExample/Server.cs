using System;
using System.Linq;
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

        public void ReceiveHybridMessage(EncryptedPacket encryptedPacket)
        {
            byte[] aesKey = Helper.RsaDecrypt(RsaParameters, encryptedPacket.RsaEncryptedAesKey);
            byte[] validationHmac = Helper.GenerateHmac(aesKey, encryptedPacket.AesEncryptedData);

            if (!encryptedPacket.Hmac.SequenceEqual(validationHmac))
                throw new CryptographicException("Hmac doesn't match for encrypted packet.");

            string message = Helper.AesDecrypt(aesKey, encryptedPacket.Iv, encryptedPacket.AesEncryptedData);

            Console.WriteLine(message);
        }
    }
}
