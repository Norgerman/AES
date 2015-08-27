using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using AES;

namespace Test
{
    public class Test
    {
        [Fact]
        public void TestAdd()
        {
            Assert.Equal(1, 1);
        }

        [Fact]
        public void TestEncrypt_CBC_PKCS7()
        {
            byte[] iv = Convert.FromBase64String("54bRC9RGKfFxZMbk67B1Ow==");

            byte[] key = new byte[32]{0xAB,0xDD,0x4E,0x18,0xF4,0xC2,0x82,0xA2,
                                      0xCF,0xDB,0x98,0x74,0x2B,0x53,0x1D,0x02,
                                      0x92,0x0F,0x98,0x3B,0x34,0x3B,0xFF,0xBA,
                                      0xA4,0x67,0x28,0x1D,0xC9,0xB5,0x70,0x41};
            string s = "abcdefghijklmnop";
            using (AesProvider aesp = new AesProvider(key, iv))
            {
                var enc1 = aesp.Encrypt(s);
                var bs = Encoding.UTF8.GetBytes(s);
                var enc2 = aesp.EncryptSingleBlock(bs, 0, bs.Length);
                Assert.Equal(enc1, enc2);
                Assert.Equal(s, aesp.Decrypt(enc2));
                aesp.Padding = System.Security.Cryptography.PaddingMode.None;
                var dec = aesp.DecryptSingleBlock(enc1, 0, enc1.Length);
                Assert.Equal(16 - bs.Length % 16, dec.Last());
                Assert.Equal(32, dec.Length);
            }
        }

        [Fact]
        public void TestEncrypt_ECB_PKCS7()
        {
            byte[] iv = Convert.FromBase64String("54bRC9RGKfFxZMbk67B1Ow==");

            byte[] key = new byte[32]{0xAB,0xDD,0x4E,0x18,0xF4,0xC2,0x82,0xA2,
                                      0xCF,0xDB,0x98,0x74,0x2B,0x53,0x1D,0x02,
                                      0x92,0x0F,0x98,0x3B,0x34,0x3B,0xFF,0xBA,
                                      0xA4,0x67,0x28,0x1D,0xC9,0xB5,0x70,0x41};
            string s = "a";
            using (AesProvider aesp = new AesProvider(key, iv))
            {
                aesp.Mode = System.Security.Cryptography.CipherMode.ECB;
                var enc1 = aesp.Encrypt(s);
                var bs = Encoding.UTF8.GetBytes(s);
                var enc2 = aesp.EncryptSingleBlock(bs, 0, bs.Length);
                Assert.Equal(enc1, enc2);
                Assert.Equal(s, aesp.Decrypt(enc2));
                aesp.Padding = System.Security.Cryptography.PaddingMode.None;
                var dec = aesp.DecryptSingleBlock(enc1, 0, enc1.Length);
                Assert.Equal(16 - bs.Length % 16, dec.Last());
                Assert.Equal(16, dec.Length);
            }
        }

        [Fact]
        public void TestEncrypt_CFB_PKCS7()
        {
            byte[] iv = Convert.FromBase64String("54bRC9RGKfFxZMbk67B1Ow==");

            byte[] key = new byte[32]{0xAB,0xDD,0x4E,0x18,0xF4,0xC2,0x82,0xA2,
                                      0xCF,0xDB,0x98,0x74,0x2B,0x53,0x1D,0x02,
                                      0x92,0x0F,0x98,0x3B,0x34,0x3B,0xFF,0xBA,
                                      0xA4,0x67,0x28,0x1D,0xC9,0xB5,0x70,0x41};
            string s = "a";
            using (AesProvider aesp = new AesProvider(key, iv))
            {
                aesp.Mode = System.Security.Cryptography.CipherMode.CFB;
                var enc1 = aesp.Encrypt(s);
                var bs = Encoding.UTF8.GetBytes(s);
                var enc2 = aesp.EncryptSingleBlock(bs, 0, bs.Length);
                Assert.Equal(enc1, enc2);
                Assert.Equal(s, aesp.Decrypt(enc2));
                aesp.Padding = System.Security.Cryptography.PaddingMode.None;
                var dec = aesp.DecryptSingleBlock(enc1, 0, enc1.Length);
                Assert.Equal(16 - bs.Length % 16, dec.Last());
                Assert.Equal(16, dec.Length);
            }
        }

        [Fact]
        public void TestEncrypt_CBC_Zeros()
        {
            byte[] iv = Convert.FromBase64String("54bRC9RGKfFxZMbk67B1Ow==");

            byte[] key = new byte[32]{0xAB,0xDD,0x4E,0x18,0xF4,0xC2,0x82,0xA2,
                                      0xCF,0xDB,0x98,0x74,0x2B,0x53,0x1D,0x02,
                                      0x92,0x0F,0x98,0x3B,0x34,0x3B,0xFF,0xBA,
                                      0xA4,0x67,0x28,0x1D,0xC9,0xB5,0x70,0x41};
            string s = "abcdefghijklmnop";
            using (AesProvider aesp = new AesProvider(key, iv))
            {
                aesp.Padding = System.Security.Cryptography.PaddingMode.Zeros;
                var enc1 = aesp.Encrypt(s);
                var bs = Encoding.UTF8.GetBytes(s);
                var enc2 = aesp.EncryptSingleBlock(bs, 0, bs.Length);
                Assert.Equal(enc1, enc2);
                Assert.Equal(s, aesp.Decrypt(enc2));
                aesp.Padding = System.Security.Cryptography.PaddingMode.None;
                var dec = aesp.DecryptSingleBlock(enc1, 0, enc1.Length);
                Assert.NotEqual(0, dec.Last());
                Assert.Equal(16, dec.Length);
            }
        }

        [Fact]
        public void TestEncrypt_ECB_Zeros()
        {
            byte[] iv = Convert.FromBase64String("54bRC9RGKfFxZMbk67B1Ow==");

            byte[] key = new byte[32]{0xAB,0xDD,0x4E,0x18,0xF4,0xC2,0x82,0xA2,
                                      0xCF,0xDB,0x98,0x74,0x2B,0x53,0x1D,0x02,
                                      0x92,0x0F,0x98,0x3B,0x34,0x3B,0xFF,0xBA,
                                      0xA4,0x67,0x28,0x1D,0xC9,0xB5,0x70,0x41};
            string s = "a";
            using (AesProvider aesp = new AesProvider(key, iv))
            {
                aesp.Mode = System.Security.Cryptography.CipherMode.ECB;
                aesp.Padding = System.Security.Cryptography.PaddingMode.Zeros;
                var enc1 = aesp.Encrypt(s);
                var bs = Encoding.UTF8.GetBytes(s);
                var enc2 = aesp.EncryptSingleBlock(bs, 0, bs.Length);
                Assert.Equal(enc1, enc2);
                Assert.Equal(s, aesp.Decrypt(enc2).TrimEnd('\0'));
                aesp.Padding = System.Security.Cryptography.PaddingMode.None;
                var dec = aesp.DecryptSingleBlock(enc1, 0, enc1.Length);
                Assert.Equal(0, dec.Last());
                Assert.Equal(16, dec.Length);
            }
        }

        [Fact]
        public void TestEncrypt_CFB_Zeros()
        {
            byte[] iv = Convert.FromBase64String("54bRC9RGKfFxZMbk67B1Ow==");

            byte[] key = new byte[32]{0xAB,0xDD,0x4E,0x18,0xF4,0xC2,0x82,0xA2,
                                      0xCF,0xDB,0x98,0x74,0x2B,0x53,0x1D,0x02,
                                      0x92,0x0F,0x98,0x3B,0x34,0x3B,0xFF,0xBA,
                                      0xA4,0x67,0x28,0x1D,0xC9,0xB5,0x70,0x41};
            string s = "a";
            using (AesProvider aesp = new AesProvider(key, iv))
            {
                aesp.Mode = System.Security.Cryptography.CipherMode.CFB;
                aesp.Padding = System.Security.Cryptography.PaddingMode.Zeros;
                var enc1 = aesp.Encrypt(s);
                var bs = Encoding.UTF8.GetBytes(s);
                var enc2 = aesp.EncryptSingleBlock(bs, 0, bs.Length);
                Assert.Equal(enc1, enc2);
                Assert.Equal(s, aesp.Decrypt(enc2).TrimEnd('\0'));
                aesp.Padding = System.Security.Cryptography.PaddingMode.None;
                var dec = aesp.DecryptSingleBlock(enc1, 0, enc1.Length);
                Assert.Equal(0, dec.Last());
                Assert.Equal(16, dec.Length);
            }
        }
    }
}
