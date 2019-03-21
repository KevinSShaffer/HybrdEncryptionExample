using System.Security.Cryptography;

namespace HybridEncryptionExample
{
    public class Client
    {
        private byte[] Secret { get; set; }
        private RSAParameters PrivateKey { get; set; }
        public RSAParameters PublicKey { get; private set; }

        public Client()
        {
            Secret = Helper.GenerateRandom(32);

            using (var rsa = new RSACryptoServiceProvider())
            {
                PublicKey = rsa.ExportParameters(false);
                PrivateKey = rsa.ExportParameters(true);
            }
        }

        public void SendMessage(Server server, string message)
        {
            byte[] iv = Helper.GenerateRandom(16);
            byte[] aesEncryptedMessage = Helper.AesEncrypt(Secret, iv, message);
            byte[] hmac = Helper.GenerateHmac(Secret, aesEncryptedMessage);
            byte[] rsaEncryptedAesKey = Helper.RsaEncrypt(server.PublicKey, Secret);
            byte[] signature = Helper.SignData(PrivateKey, hmac);

            server.ReceiveHybridMessage(this, new EncryptedPacket(rsaEncryptedAesKey, iv, hmac, aesEncryptedMessage, signature));
        }
    }
}
