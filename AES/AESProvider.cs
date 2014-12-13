using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;

namespace AES
{
    /// <summary>
    /// Provider AES crypt service
    /// default keysize is 256(in bits)
    /// valid keysize 128 192 256(in bits)
    /// default mode is cbc
    /// default paddingmode is pkcs7
    /// </summary>
    public sealed class AESProvider : Aes
    {
        private byte[] m_temp;

        /// <summary>
        /// Create a instance use random key and iv
        /// </summary>
        public AESProvider()
            : base()
        {
            this.Mode = CipherMode.CBC;
            this.Padding = PaddingMode.PKCS7;
            this.KeySize = 256;
        }

        /// <summary>
        /// Use given key and IV to create a instance
        /// keysize depends on the length of key in bits
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="iv">IV</param>
        public AESProvider(byte[] key, byte[] iv)
            : base()
        {
            this.Mode = CipherMode.CBC;
            this.Padding = PaddingMode.PKCS7;
            this.Key = key;
            this.IV = iv;
        }

        /// <summary>
        /// Encrypt a string
        /// </summary>
        /// <param name="plaintext">the string to encrypt</param>
        /// <returns>the ciphertext of the string(in byte)</returns>
        public byte[] Encrypt(string plaintext)
        {
            if (plaintext == null || plaintext.Length <= 0)
            {
                return null;
            }

            byte[] encrypted;
            byte[] plaintextb = Encoding.UTF8.GetBytes(plaintext);

            ICryptoTransform encryptor = this.CreateEncryptor();

            MemoryStream msEcrypt = new MemoryStream();
            CryptoStream csEncrypt = new CryptoStream(msEcrypt, encryptor, CryptoStreamMode.Write);

            try
            {
                csEncrypt.Write(plaintextb, 0, plaintextb.Length);
                csEncrypt.FlushFinalBlock();
            }
            finally
            {
                csEncrypt.Dispose();
                encrypted = msEcrypt.ToArray();
                msEcrypt.Dispose();
            }

            return encrypted;
        }

        /// <summary>
        /// to decrypt bytes to string
        /// </summary>
        /// <param name="cipher">bytes of ciphertext</param>
        /// <returns>the plaintext</returns>
        public string Decrypt(byte[] cipher)
        {
            if (cipher == null || cipher.Length <= 0)
            {
                return null;
            }

            string plaintext;
            ICryptoTransform decryptor = this.CreateDecryptor();

            using (MemoryStream msDecrypt = new MemoryStream(cipher))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt, Encoding.UTF8))
            {
                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }

        /// <summary>
        /// PaddingMode PCKS7(cannot change)
        /// </summary>
        /// <param name="inputbuffer">bytes to encrypt</param>
        /// <param name="offset">the start position of the bytes</param>
        /// <param name="count">count of bytes(must be a multiple of 16)</param>
        /// <returns>bytes after encrypted</returns>
        public byte[] EncryptBlock(byte[] inputbuffer, int offset, int count)
        {
            ICryptoTransform encryptor;
            MemoryStream ms;
            CryptoStream cs;
            byte[] encrypted;

            if (m_temp == null)
            {
                m_temp = new byte[16];
                this.IV.CopyTo(m_temp, 0);
            }

            this.Padding = PaddingMode.None;
            encryptor = this.CreateEncryptor(this.Key, this.m_temp);

            ms = new MemoryStream();
            cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

            try
            {
                cs.Write(inputbuffer, offset, count);
                cs.FlushFinalBlock();
                ms.Seek(-16, SeekOrigin.End);
                ms.Read(m_temp, 0, 16);
            }
            finally
            {
                cs.Close();
                encrypted = ms.ToArray();
                ms.Close();
            }

            return encrypted;
        }

        /// <summary>
        /// to encrypt the final bytes
        /// PaddingMode PCKS7(cannot change)
        /// </summary>
        /// <param name="inputbuffer">bytes to encrypt</param>
        /// <param name="offset">the start position of the bytes</param>
        /// <param name="count">count of bytes</param>
        /// <returns>bytes after encrypted</returns>
        public byte[] EncryptFinalBlock(byte[] inputbuffer, int offset, int count)
        {
            ICryptoTransform encryptor;
            MemoryStream ms;
            CryptoStream cs;
            byte[] encrypted;

            if (m_temp == null)
            {
                m_temp = new byte[16];
                this.IV.CopyTo(m_temp, 0);
            }

            this.Padding = PaddingMode.PKCS7;
            encryptor = this.CreateEncryptor(this.Key, this.m_temp);

            ms = new MemoryStream();
            cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

            try
            {
                cs.Write(inputbuffer, offset, count);
                cs.FlushFinalBlock();
            }
            finally
            {
                m_temp = null;
                cs.Close();
                encrypted = ms.ToArray();
                ms.Close();
            }

            return encrypted;
        }

        /// <summary>
        /// PaddingMode PCKS7(cannot change)
        /// </summary>
        /// <param name="inputbuffer">bytes to decrypt</param>
        /// <param name="offset">the start position of the bytes</param>
        /// <param name="count">count of bytes(must be a multiple of 16)</param>
        /// <returns>bytes after decrypted</returns>
        public byte[] DecryptBlock(byte[] inputbuffer, int offset, int count)
        {
            ICryptoTransform decryptor;
            MemoryStream ms;
            CryptoStream cs;
            byte[] decrypted;

            if (m_temp == null)
            {
                m_temp = new byte[16];
                this.IV.CopyTo(m_temp, 0);
            }

            this.Padding = PaddingMode.None;
            decryptor = this.CreateDecryptor(this.Key, this.m_temp);

            using (ms = new MemoryStream(inputbuffer, offset, count))
            using (cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            {
                ms.Seek(-16, SeekOrigin.End);
                ms.Read(m_temp, 0, 16);

                ms.Seek(0, SeekOrigin.Begin);

                decrypted = new byte[count];
                cs.Read(decrypted, 0, count);
            }

            return decrypted;
        }

        /// <summary>
        /// to decrypt the final bytes
        /// PaddingMode PCKS7(cannot change)
        /// </summary>
        /// <param name="inputbuffer">bytes to decrypt</param>
        /// <param name="offset">the start position of the bytes</param>
        /// <param name="count">count of bytes</param>
        /// <returns>bytes after decrypted</returns>
        public byte[] DecryptFinalBlock(byte[] inputbuffer, int offset, int count)
        {
            ICryptoTransform decryptor;
            MemoryStream ms;
            CryptoStream cs;
            int len;
            byte[] decrypted;

            if (m_temp == null)
            {
                m_temp = new byte[16];
                this.IV.CopyTo(m_temp, 0);
            }

            this.Padding = PaddingMode.PKCS7;
            decryptor = this.CreateDecryptor(this.Key, this.m_temp);

            using (ms = new MemoryStream(inputbuffer, offset, count))
            using (cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            {
                decrypted = new byte[count];
                len = cs.Read(decrypted, 0, count);
                m_temp = null;
            }

            return decrypted.Take(len).ToArray();
        }

        /// <summary>
        /// Use Key and IV(if no key or IV, will generate one) to create a decryptor
        /// </summary>
        /// <returns>decryptor</returns>
        public override ICryptoTransform CreateDecryptor()
        {
            if (this.Key == null)
            {
                this.GenerateKey();
            }
            if (this.IV == null)
            {
                this.GenerateIV();
            }

            return this.CreateDecryptor(this.Key, this.IV);
        }

        /// <summary>
        /// Use given Key and IV to create a decryptor
        /// </summary>
        /// <param name="rgbKey">Key</param>
        /// <param name="rgbIV">IV</param>
        /// <returns>decryptor</returns>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            using (AesCryptoServiceProvider _acsp = new AesCryptoServiceProvider())
            {
                _acsp.Padding = this.Padding;
                _acsp.Mode = this.Mode;
                return _acsp.CreateDecryptor(rgbKey, rgbIV);
            }
        }

        /// <summary>
        /// Use Key and IV(if no key or IV, will generate one) to create a encryptor
        /// </summary>
        /// <returns>encryptor</returns>
        public override ICryptoTransform CreateEncryptor()
        {
            if (this.Key == null)
            {
                this.GenerateKey();
            }
            if (this.IV == null)
            {
                this.GenerateIV();
            }

            return this.CreateEncryptor(this.Key, this.IV);
        }

        /// <summary>
        /// Use given Key and IV to create a encryptor
        /// </summary>
        /// <param name="rgbKey">Key</param>
        /// <param name="rgbIV">IV</param>
        /// <returns>encryptor</returns>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            using (AesCryptoServiceProvider _acsp = new AesCryptoServiceProvider())
            {
                _acsp.Padding = this.Padding;
                _acsp.Mode = this.Mode;
                return _acsp.CreateEncryptor(rgbKey, rgbIV);
            }
        }

        /// <summary>
        /// Generate an IV
        /// </summary>
        public override void GenerateIV()
        {
            using (AesCryptoServiceProvider _acsp = new AesCryptoServiceProvider())
            {
                _acsp.BlockSize = this.BlockSize;
                _acsp.GenerateIV();
                this.IV = _acsp.IV;
            }
        }

        /// <summary>
        /// Generate a key(default keysize is 256)
        /// </summary>
        public override void GenerateKey()
        {
            using (AesCryptoServiceProvider _acsp = new AesCryptoServiceProvider())
            {
                _acsp.KeySize = this.KeySize;
                _acsp.GenerateKey();
                this.Key = _acsp.Key;
            }
        }
    }
}
