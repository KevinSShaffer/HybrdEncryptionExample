using System;

namespace HybridEncryptionExample
{
    class Program
    {
        static void Main(string[] args)
        {
            var server = new Server();
            var client = new Client();

            client.SendMessage(server, "This is a super secret message!");

            Console.ReadKey();
        }
    }    
}
