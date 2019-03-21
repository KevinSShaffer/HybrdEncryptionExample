namespace HybridEncryptionExample
{
    public struct EncryptedPacket
    {
        public byte[] RsaEncryptedAesKey;
        public byte[] Iv;
        public byte[] Hmac;
        public byte[] AesEncryptedData;

        public EncryptedPacket(byte[] key, byte[] iv, byte[] hmac, byte[] data)
        {
            RsaEncryptedAesKey = key;
            Iv = iv;
            Hmac = hmac;
            AesEncryptedData = data;
        }
    }
}
