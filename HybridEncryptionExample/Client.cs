﻿namespace HybridEncryptionExample
{
    public class Client
    {
        private byte[] Secret { get; set; }

        public Client()
        {
            Secret = Helper.GenerateRandom(32);
        }

        public void SendMessage(Server server, string message)
        {
            byte[] iv = Helper.GenerateRandom(16);
            byte[] aesEncryptedMessage = Helper.AesEncrypt(Secret, iv, message);
            byte[] hmac = Helper.GenerateHmac(Secret, aesEncryptedMessage);
            byte[] rsaEncryptedAesKey = Helper.RsaEncrypt(server.PublicParameters, Secret);

            server.ReceiveHybridMessage(new EncryptedPacket(rsaEncryptedAesKey, iv, hmac, aesEncryptedMessage));
        }
    }
}
