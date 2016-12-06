using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSACrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            string input = "";
            var crypto = new Crypto();
            var keyPair = crypto.GetRandom4096BitRSAKey();
            var pubXML = keyPair.PublicKey;
            var privXML = keyPair.PrivateKey;              
            if (string.IsNullOrEmpty(pubXML))
            {
                Console.WriteLine("No public key, exiting program");
                Console.ReadKey();
            }
            else if (string.IsNullOrEmpty(privXML))
            {
                Console.WriteLine("No private key, exiting program");
                Console.ReadKey();
            }
            while (!input.Equals("quit"))
            {
                Console.WriteLine("Type e to encrypt or d to decrypt or quit to exit");
                input = Console.ReadLine();
                switch (input)
                {
                    case "e":
                    case "E":
                        Encrypt(pubXML);
                        break;
                    case "d":
                    case "D":
                        Decryot(privXML);
                        break;
                    default:
                        Console.WriteLine("Type e to encrypt or d to decrypt or quit to exit");
                        break;
                }
            }
        }

        private static void Decryot(string privXML)
        {
            Console.WriteLine("Yo! You chose to decrypt, enter any text to decrypt.");
            var cipherText = Console.ReadLine();
            var plainText = new Crypto().Decrypt(privXML, cipherText);
            Console.WriteLine("Decrypted Value:");
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine(plainText);
        }

        private static void Encrypt(string pubXML)
        {
            Console.WriteLine("Cool! You chose to encrypt, enter any text to encrypt.");
            var plainText = Console.ReadLine();
            var cipherText = new Crypto().Encrypt(pubXML, plainText);
            Console.WriteLine("Encrypted Value:");
            Console.WriteLine("--------------------------------------------------");
            Console.WriteLine(cipherText);
        }
    }
}
