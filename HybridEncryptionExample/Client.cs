using System.Security.Cryptography;

namespace HybridEncryptionExample
{
    public class Client
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
            byte[] iv = Helper.GenerateAesIv();
            byte[] rsaEncryptedAesKey = Helper.RsaEncrypt(server.PublicParameters, Secret);

            server.ReceiveHybridMessage(rsaEncryptedAesKey, iv, Helper.AesEncrypt(Secret, iv, message));
        }
    }
}
