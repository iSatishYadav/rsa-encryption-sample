using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RSACrypt;

namespace RSACrypto.Test
{
    [TestClass]
    public class CryptoTest
    {
        [TestMethod]
        public void EncrptionDecryptionTest()
        {
            var publicKey = "<RSAKeyValue><Modulus>Sle+fyrA0U8oSTj9zWvdGYTK+Q5POCLUAdqTjlOkVpRM1KsZ9w5aCcNfyA+FTUlyptHl8v7jh8p2fh8yjOen1u396LLULve95FwtaVvKwndRUrnRbnsP/GdKmNYEQ6qkrKUTzy27gw8xidQuefkcK/GCopl+xCGjLNOHKTfxxtdV5tGK+bV7X2L3GhCH9bVRYRRKAhHxdKqmVgMYQOedb+J4n7fdFJLi3pOoJEZlVFhccN+c/dhVabf06w1ZQwktFX1fEaVloQvewEeLW8xOYpCjlaKbvQzaSH9r4DtwBta9pZXwArRF84oUSU7A5sv59fxJ5i3wmW2uBfaKsKHaJKhXwqa2+dKpTbZwPmDBZWoQNdRmS4TeFsFLX9RLFVep1BarYD6lnP/fAO7pdL8yTqa7dE71qTWvFNmVqa4yi9PAiNPKr28tMmRRPyGgXwHuUzi6CMELKZR/XPska5nMOhi8gUX0C0o0HOcno4Sb41Z/o7Q32SkfLyayHUCSKl7oxLt72jTh0KCW1goukFAq1cOduqWAktQubj1WBQ2eE62W1LOvaDTzcwqb1n7/oosb3agQ5+UwEVzHk8KvGx1juTO4tmuWKWMkHapi0l4TtXDvVZhBI+YUDFj7Dyy1RMaD18YkM3gFqJaPV/J9Abcl9CM1eFyrO2RL4VGFjjc0jMM=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            var privateKey = "<RSAKeyValue><Modulus>Sle+fyrA0U8oSTj9zWvdGYTK+Q5POCLUAdqTjlOkVpRM1KsZ9w5aCcNfyA+FTUlyptHl8v7jh8p2fh8yjOen1u396LLULve95FwtaVvKwndRUrnRbnsP/GdKmNYEQ6qkrKUTzy27gw8xidQuefkcK/GCopl+xCGjLNOHKTfxxtdV5tGK+bV7X2L3GhCH9bVRYRRKAhHxdKqmVgMYQOedb+J4n7fdFJLi3pOoJEZlVFhccN+c/dhVabf06w1ZQwktFX1fEaVloQvewEeLW8xOYpCjlaKbvQzaSH9r4DtwBta9pZXwArRF84oUSU7A5sv59fxJ5i3wmW2uBfaKsKHaJKhXwqa2+dKpTbZwPmDBZWoQNdRmS4TeFsFLX9RLFVep1BarYD6lnP/fAO7pdL8yTqa7dE71qTWvFNmVqa4yi9PAiNPKr28tMmRRPyGgXwHuUzi6CMELKZR/XPska5nMOhi8gUX0C0o0HOcno4Sb41Z/o7Q32SkfLyayHUCSKl7oxLt72jTh0KCW1goukFAq1cOduqWAktQubj1WBQ2eE62W1LOvaDTzcwqb1n7/oosb3agQ5+UwEVzHk8KvGx1juTO4tmuWKWMkHapi0l4TtXDvVZhBI+YUDFj7Dyy1RMaD18YkM3gFqJaPV/J9Abcl9CM1eFyrO2RL4VGFjjc0jMM=</Modulus><Exponent>AQAB</Exponent><P>j1Mi3TS8HHdkDWzMxtyR4/t+i4C3B6qO4xlFo+KcMpi9UI0EmQpj/Oez3uTpMfJOja+c+On1wN5kUftmtIE8LWHhdyyrbr0JnZd3s6lfV4OqkzXYN/B1qVagek71L24C3L9enzJ6VuEXkWiOukVB4AANcIUPEmtdjiT/yGR/uV9VqrSyniK60P8frNAs+rZJrWck3Jd+tiYOq6fLM7S8FeOC7AQAetTWaT0gxNM0ucPMnj8t+F0/eG2Kjs+1lOWBQ4FYh4xPqwPGx7IDTrjJ4pKfuhawNqopUBOFirJwZQvKhOQutyGwy2w0I6TOrKyNuTMThC/niNuxngs3mIrMMQ==</P><Q>hMmdnoSDDXuff3M4uGb5eg7g0Ujo5KLit9puHA4QGrNdgebEc0lbbgO4UcML0n7+9FUZcdFaK3BgBtQKuJW+nYPz3RiEnP4jMa+gr5RhWO3Ofmr4YrTA3BxizXRpuTKnRnZUQlpbbfQSSC2rE1MY2M9HblmRWs+aSmqSh0SaPcpeadrjvcmvHlLxp0FdSM8FYySVpDp0ME0LWTdXXguPZhT0t/ayGeTFqKBT4ujEK2RPFUxdKq5ke4zZuAtKw5gyPC4CvWDGTxWRDjnNnRxailLyy0dO9Yzsk/6dgjZr+5+G+rjqBs5zvMkqGmMIFpP5DZpQ2LKHKlLme3OZEEcPMw==</Q><DP>NURbr8TaqOXCfK7UCJCPdCDTLju/So0cH9ETrc4Z6UAVFCvk6pAPCz59/jgrZxG8GjKLb4Ncf7rnpASAblOdruwy5Jzodfax7S0PIumu8pKPwbiATIIE6NO2Pt67h04mqC5Dl30mNMXhgXxPl3EIA51hYVFCgcD/e0XK/opDYfzJlPEldVpI/kXjWtHf9ansBhNQgt+XC1FnoGpzPhtM0AHHdbojB4O00FYUqLIqZWQc1y96AVV+sl5b4anWvajyeslGwtHmBhQYO72wNwC8n4WI8ZtfEGH7irRGrH6XASb5tJwttIhD8cacNicZXNmgrpUKCtXXAmlMQQXAOuRS8Q==</DP><DQ>GJwNHD3O1AbfTo2aK4LaJabwP5lVoFoXzp8q3QQ2M9yeLd8I9ZzY1xDVbkHJxR9IPRwwdQmpvnc7NMjDm+YUx7iWz5klqrrm5uR30VKcoBCivocwtYpuW9ze6tjyZyJeIg74GrwISd58LOhZ1mEGL9hqkqcC62OiYrxRn8Q1GdKRoOiyYJAqZmJU6vyQP1gu1WsIWMGEmxcMTWKWTJWz4+VqXVXZODdP8qqUIW+mO6yBg579fVWIxeUazKM7HfjtBn44f8SZvDpxAcPwuXdxyEULPmVe2t9dUShVJLbVWHL+XyU6KjzE8m4N4YoNC7Is7Dp3VVHw/wUSNjr8WSnyRQ==</DQ><InverseQ>fsTGxvFBgTm0B0Zb4tTBUnh5Ta2VXPtU8wck3/VBhKj3sg7jHZOMt6HMAgFfT9cxAexXb/SMTkrNOjs3XhD8TLkqUxykdoUogu0gxgPtN8Y281K/mxzqlPM/ixpzHN3LdpP/iOFcIvRaqJJiugy2X+njj9zxsogxbw7/LSLoXue1jf85j4nXaRLU6jHTBcO9IfyaM/pk1mdFYKMXX9DSRtg0KVEW40zY2ISjvmr2xJZnawlkXZMbt+A5iaDIt3O1xclZIRGX8GU8pyHb7+58A9K01NAftq9U3kqXcDqfQBVXF6hmIuVJjuG27OYrqBXoiRNrUFSUWt8XCFnopHg2FQ==</InverseQ><D>Q2spRZfW/rpDdYvqluUPwHmtvIkejHEBRKEdGYB+00lwF5kHVgY83wfAD+ULZViLUf+eAmzmmJmiNaRDKodWrVJs5h9uzx06pyJ0yExHJ24fYN9Er2WIzMQ7YTkM6vSQnESkH0mA+EzKBw1WDKU9yBgf+ScsT9+VZCx8MYQbjdBwhX9YAjZzqMBOCOQe+FOzdk95AkGVb9DmQbBSyWGCZBnEfEu4gVTnyyOq4yK39/Kd+nq/m3EZnGMICDW10lY6/XcRxSXycUcbfdIj7l7sYvR6dVPe2mYSepablOEyKfGKUOUVoM4tdbutxAFYbLVkfJCLz+OvguR1YdEAW0icU5G0pbWpHiKsFbt1oC/V+uzWSnV0riUQX8TS0youB34wGrhjlYk7tq/C6gxTx+rr5waNds3HoHsrjjYKDK/2uOOHuiqWPT1JBQjxCMu1EZAioo+8jjA8Wl02PQ6wn1r4f3gRBZEGDAJkZhTS30TqPnWKkyNl4055mzIPn2L0aT08h3RpZOoXOkbeb2ocDgVgAzTXySt69WwZazo9jgz4xvlAfXKl1eR1L5+qv34BTZNC6IzAeKtTb6kQEtTAOHqBg4COz4vS3thuvZN9TOF3HfnEhJTXStIHMbY6GRCJRc++uZ6yHSnOI1EEhbACZa6DTFb1x9U6G28veNwHONYsaGE=</D></RSAKeyValue>";
            var crypto = new Crypto();

            for (int i = 0; i < 100; i++)
            {

                var plainText = crypto.GetRandomString();
                var cipher = crypto.Encrypt(publicKey, plainText);
                var decrypted = crypto.Decrypt(privateKey, cipher);
                Assert.AreEqual(plainText, decrypted); 
            }
        }
    }
}
