using System;
using System.Linq;
using System.Security.Cryptography;

namespace HybridEncryptionExample
{
    public class Server
    {
        private RSAParameters PrivateKey { get; set; }
        public RSAParameters PublicKey { get; private set; }

        public Server()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                PublicKey = rsa.ExportParameters(false);
                PrivateKey = rsa.ExportParameters(true);
            }
        }

        public void ReceiveHybridMessage(Client client, EncryptedPacket encryptedPacket)
        {
            byte[] aesKey = Helper.RsaDecrypt(PrivateKey, encryptedPacket.RsaEncryptedAesKey);
            byte[] validationHmac = Helper.GenerateHmac(aesKey, encryptedPacket.AesEncryptedData);

            if (!encryptedPacket.Hmac.SequenceEqual(validationHmac))
                throw new CryptographicException("Hmac doesn't match for encrypted packet.");
            else if (!Helper.VerifySignature(client.PublicKey, encryptedPacket.Signature, encryptedPacket.Hmac))
                throw new CryptographicException("Unable to verify signature.");

            string message = Helper.AesDecrypt(aesKey, encryptedPacket.Iv, encryptedPacket.AesEncryptedData);

            Console.WriteLine(message);
        }
    }
}
