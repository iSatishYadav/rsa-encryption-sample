using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RSACrypt
{
    public class RSAKeyPair
    {
        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }
    }

    public class Crypto
    {

        public  string GetRandomString(int length)
        {
            return GetRandomStringHelper(length);
        }

        public string GetRandomString()
        {
            return GetRandomStringHelper(-1);
        }

        private static string GetRandomStringHelper(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789qwertyuiopasdfghjklzxcvbnmm~!@#$%^&*()_-`][\';,./?><";
            var random = new Random();
            if (length == -1)
            {
                length = random.Next(1, 100);
            }
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public RSAKeyPair GetRandom4096BitRSAKey()
        {
            using (var rsa = new RSACryptoServiceProvider(4096))
            {
                var pair = new RSAKeyPair { PrivateKey = rsa.ToXmlString(true), PublicKey = rsa.ToXmlString(false) };
                return pair;
            }
        }

        public string Encrypt(string publicKeyXML, string plainText)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKeyXML);
                var plainBytes = Encoding.ASCII.GetBytes(plainText);
                var cipherBytes = rsa.Encrypt(plainBytes, false);
                var cipherText = Convert.ToBase64String(cipherBytes);
                return cipherText;
            }
        }

        public string Decrypt(string publicPrivateKeyXML, string cipherText)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicPrivateKeyXML);
                var cipherBytes = Convert.FromBase64String(cipherText);
                var plainBytes = rsa.Decrypt(cipherBytes, false);
                var plainText = Encoding.ASCII.GetString(plainBytes);
                return plainText;
            }
        }
    }
}