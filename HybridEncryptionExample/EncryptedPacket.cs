namespace HybridEncryptionExample
{
    public struct EncryptedPacket
    {
        public byte[] RsaEncryptedAesKey;
        public byte[] Iv;
        public byte[] Hmac;
        public byte[] AesEncryptedData;
        public byte[] Signature;

        public EncryptedPacket(byte[] key, byte[] iv, byte[] hmac, byte[] data, byte[] signature)
        {
            RsaEncryptedAesKey = key;
            Iv = iv;
            Hmac = hmac;
            AesEncryptedData = data;
            Signature = signature;
        }
    }
}
