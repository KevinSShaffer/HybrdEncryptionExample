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
}
