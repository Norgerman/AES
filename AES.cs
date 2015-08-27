using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

/// <summary>
/// AlgrothmTestClass
/// </summary>
namespace AES
{
    public enum Keysize : byte { Bits128, Bits192, Bits256 }

    public class AesProvider
    {
        private int Nb, Nk, Nr;
        private byte[] key;
        private byte[,] Sbox;
        private byte[,] iSbox;
        private byte[,] w;
        private byte[,] Rcon;
        private byte[,] State;
        private byte[] IV;
        private byte[] m_temp;

        /// <summary>
        /// constructor
        /// </summary>
        /// <param name="keysize">Enum Bits128,Bits192 or Bits256</param>
        /// <param name="keyBytes">ByteArray of key(16,24 or 32 bytes)</param>
        /// <param name="IVBytes">Initialization Vector 16 bytes</param>
        public AesProvider(Keysize keysize, byte[] keyBytes, byte[] IVBytes)
        {
            setNbNkNr(keysize);

            this.key = new byte[4 * this.Nk];
            keyBytes.CopyTo(this.key, 0);
            IV = (byte[])IVBytes.Clone();

            BuildSbox();
            BuildInvSbox();
            BulidRcon();

            KeyExpansion();
        }

        public byte[] Encrypt(string context)
        {
            byte[] plaintext = Encoding.UTF8.GetBytes(context);
            List<byte> encrypted = new List<byte>();
            byte[] buffer = new byte[16];
            byte[] output = new byte[16];
            byte[] mask = new byte[16];
            byte padding = (byte)(16 - plaintext.Length % 16);
            byte[] appending = new byte[padding];

            IV.CopyTo(mask, 0);

            for (int i = 0; i < padding; i++)
            {
                appending[i] = padding;
            }

            try
            {
                using (MemoryStream ms = new MemoryStream(plaintext.Length + appending.Length))
                {
                    ms.Write(plaintext, 0, plaintext.Length);
                    ms.Write(appending, 0, appending.Length);

                    ms.Seek(0, SeekOrigin.Begin);

                    while (ms.Read(buffer, 0, 16) > 0)
                    {

                        for (int i = 0; i < 16; i++)
                        {
                            buffer[i] = (byte)((int)buffer[i] ^ (int)mask[i]);
                        }


                        this.Cipher(buffer, output);

                        output.CopyTo(mask, 0);

                        encrypted.AddRange(output);
                    }
                }

                return encrypted.ToArray();
            }
            finally
            {
                //GC.Collect();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputbuffer">bytes to encrypt</param>
        /// <param name="count">count of bytes(must be a multiple of 16)</param>
        /// <returns>bytes after encrypted</returns>
        public byte[] EncryptBlock(byte[] inputbuffer, int count)
        {
            List<byte> encrypted = new List<byte>();
            byte[] output = new byte[16];
            byte[] buffer = new byte[16];

            if (count % 16 != 0)
            {
                throw new InvalidOperationException("Count is not a multiple of 16");
            }

            if (m_temp == null)
            {
                m_temp = new byte[16];
                IV.CopyTo(m_temp, 0);
            }

            try
            {
                using (MemoryStream ms = new MemoryStream(inputbuffer))
                {
                    while (ms.Read(buffer, 0, 16) > 0)
                    {
                        for (int i = 0; i < 16; i++)
                        {
                            buffer[i] = (byte)((int)buffer[i] ^ (int)m_temp[i]);
                        }

                        this.Cipher(buffer, output);

                        output.CopyTo(m_temp, 0);

                        encrypted.AddRange(output);
                    }
                }

                return encrypted.ToArray();
            }
            finally
            {
                //GC.Collect();
            }
        }

        /// <summary>
        /// to encrypt the final bytes
        /// </summary>
        /// <param name="inputbuffer">bytes to encrypt</param>
        /// <param name="count">count of bytes</param>
        /// <returns>bytes after encrypted</returns>
        public byte[] EncryptFinalBlock(byte[] inputbuffer, int count)
        {
            List<byte> encrypted = new List<byte>();
            byte[] output = new byte[16];
            byte[] buffer = new byte[16];
            byte padding = (byte)(16 - count % 16);
            byte[] appending = new byte[padding];

            for (int i = 0; i < padding; i++)
            {
                appending[i] = padding;
            }

            if (m_temp == null)
            {
                m_temp = new byte[16];
                IV.CopyTo(m_temp, 0);
            }

            try
            {
                using (MemoryStream ms = new MemoryStream(count + appending.Length))
                {
                    ms.Write(inputbuffer, 0, count);
                    ms.Write(appending, 0, appending.Length);

                    ms.Seek(0, SeekOrigin.Begin);

                    while (ms.Read(buffer, 0, 16) > 0)
                    {
                        for (int i = 0; i < 16; i++)
                        {
                            buffer[i] = (byte)((int)buffer[i] ^ (int)m_temp[i]);
                        }

                        this.Cipher(buffer, output);

                        output.CopyTo(m_temp, 0);

                        encrypted.AddRange(output);
                    }
                }

                return encrypted.ToArray();
            }
            finally
            {
                m_temp = null;
                //GC.Collect();
            }
        }


        public string Decrypt(byte[] cipher)
        {
            byte[] buffer = new byte[16];
            byte[] output = new byte[16];
            byte[] mask = new byte[16];
            List<byte> result = new List<byte>();

            byte[] plaintext;

            IV.CopyTo(mask, 0);

            try
            {
                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    while (ms.Read(buffer, 0, 16) > 0)
                    {
                        this.InvCipher(buffer, output);

                        for (int i = 0; i < 16; i++)
                        {
                            output[i] = (byte)((int)output[i] ^ (int)mask[i]);
                        }

                        buffer.CopyTo(mask, 0);

                        result.AddRange(output);
                    }
                }

                using (MemoryStream ms = new MemoryStream(result.ToArray()))
                {
                    plaintext = new byte[result.Count - result.Last<byte>()];
                    ms.Read(plaintext, 0, plaintext.Length);
                }

                return Encoding.UTF8.GetString(plaintext);
            }
            finally
            {
                //GC.Collect();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="inputbuffer">bytes to decrypt</param>
        /// <param name="count">count of bytes(must be a multiple of 16)</param>
        /// <returns>bytes after decrypted</returns>
        public byte[] DecryptBlock(byte[] inputbuffer, int count)
        {
            List<byte> decrypted = new List<byte>();
            byte[] buffer = new byte[16];
            byte[] output = new byte[16];

            if (count % 16 != 0)
            {
                throw new InvalidOperationException("Count is not a multiple of 16");
            }

            if (m_temp == null)
            {
                m_temp = new byte[16];
                IV.CopyTo(m_temp, 0);
            }

            try
            {
                using(MemoryStream ms=new MemoryStream(inputbuffer))
                {
                    while (ms.Read(buffer, 0, 16) > 0)
                    {
                        this.InvCipher(buffer, output);

                        for (int i = 0; i < 16; i++)
                        {
                            output[i] = (byte)((int)output[i] ^ (int)m_temp[i]);
                        }

                        buffer.CopyTo(m_temp, 0);

                        decrypted.AddRange(output);
                    }
                }

                return decrypted.ToArray();
            }
            finally
            {
                //GC.Collect();
            }
        }

        /// <summary>
        /// to decrypt the final bytes
        /// </summary>
        /// <param name="inputbuffer">bytes to decrypt</param>
        /// <param name="count">count of bytes</param>
        /// <returns>bytes after decrypted</returns>
        public byte[] DecryptFinalBlock(byte[] inputbuffer, int count)
        {
            List<byte> decrypted = new List<byte>();
            byte[] buffer = new byte[16];
            byte[] output = new byte[16];
            byte[] result;

            if (m_temp == null)
            {
                m_temp = new byte[16];
                IV.CopyTo(m_temp, 0);
            }

            try
            {
                using (MemoryStream ms = new MemoryStream(count))
                {
                    ms.Write(inputbuffer, 0, count);

                    ms.Seek(0, SeekOrigin.Begin);

                    while (ms.Read(buffer, 0, 16) > 0)
                    {
                        this.InvCipher(buffer, output);

                        for (int i = 0; i < 16; i++)
                        {
                            output[i] = (byte)((int)output[i] ^ (int)m_temp[i]);
                        }

                        buffer.CopyTo(m_temp, 0);

                        decrypted.AddRange(output);
                    }
                }

                using (MemoryStream ms = new MemoryStream(decrypted.ToArray()))
                {
                    result = new byte[decrypted.Count - decrypted.Last<byte>()];
                    ms.Read(result, 0, result.Length);
                }

                return result;
            }
            finally
            {
                m_temp = null;
                //GC.Collect();
            }
        }

        private void Cipher(byte[] input, byte[] output)
        {
            this.State = new byte[4, Nb];

            for (int i = 0; i < (4 * Nb); i++)
            {
                this.State[i % 4, i / 4] = input[i];
            }

            AddRoundKey(0);

            for (int round = 1; round <= (Nr - 1); round++)
            {
                SubBytes();
                ShiftRows();
                MixColumns();
                AddRoundKey(round);
            }

            SubBytes();
            ShiftRows();
            AddRoundKey(Nr);

            for (int i = 0; i < (4 * Nb); i++)
            {
                output[i] = State[i % 4, i / 4];
            }
        }

        private void InvCipher(byte[] input, byte[] output)
        {
            this.State = new byte[4, Nb];

            for (int i = 0; i < (4 * Nb); i++)
            {
                this.State[i % 4, i / 4] = input[i];
            }

            AddRoundKey(Nr);

            for (int round = Nr - 1; round >= 1; round--)
            {
                InvShiftRows();
                InvSubBytes();
                AddRoundKey(round);
                InvMixColumns();
            }

            InvShiftRows();
            InvSubBytes();
            AddRoundKey(0);

            for (int i = 0; i < (4 * Nb); i++)
            {
                output[i] = State[i % 4, i / 4];
            }
        }

        private void AddRoundKey(int round)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    this.State[i, j] = (byte)((int)this.State[i, j] ^ (int)this.w[round * 4 + j, i]);
                }
            }
        }

        private void SubBytes()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    this.State[i, j] = this.Sbox[this.State[i, j] >> 4, this.State[i, j] & 0x0f];
                }
            }
        }

        private void InvSubBytes()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    this.State[i, j] = this.iSbox[this.State[i, j] >> 4, this.State[i, j] & 0x0f];
                }
            }
        }

        private void ShiftRows()
        {
            byte[,] temp = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = this.State[i, j];
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    this.State[i, j] = temp[i, (j + i) % 4];
                }
            }
        }

        private void InvShiftRows()
        {
            byte[,] temp = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = this.State[i, j];
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    this.State[i, (j + i) % 4] = temp[i, j];
                }
            }
        }

        private void MixColumns()
        {
            byte[,] temp = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = this.State[i, j];
                }
            }

            for (int i = 0; i < 4; i++)
            {
                this.State[0, i] = (byte)((int)gfmultby02(temp[0, i]) ^ (int)gfmultby03(temp[1, i]) ^
                    (int)gfmultby01(temp[2, i]) ^ (int)gfmultby01(temp[3, i]));

                this.State[1, i] = (byte)((int)gfmultby01(temp[0, i]) ^ (int)gfmultby02(temp[1, i]) ^
                 (int)gfmultby03(temp[2, i]) ^ (int)gfmultby01(temp[3, i]));

                this.State[2, i] = (byte)((int)gfmultby01(temp[0, i]) ^ (int)gfmultby01(temp[1, i]) ^
                 (int)gfmultby02(temp[2, i]) ^ (int)gfmultby03(temp[3, i]));

                this.State[3, i] = (byte)((int)gfmultby03(temp[0, i]) ^ (int)gfmultby01(temp[1, i]) ^
                 (int)gfmultby01(temp[2, i]) ^ (int)gfmultby02(temp[3, i]));
            }
        }

        private void InvMixColumns()
        {
            byte[,] temp = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = this.State[i, j];
                }
            }

            for (int i = 0; i < 4; i++)
            {
                this.State[0, i] = (byte)((int)gfmultby0e(temp[0, i]) ^ (int)gfmultby0b(temp[1, i]) ^
                 (int)gfmultby0d(temp[2, i]) ^ (int)gfmultby09(temp[3, i]));

                this.State[1, i] = (byte)((int)gfmultby09(temp[0, i]) ^ (int)gfmultby0e(temp[1, i]) ^
                 (int)gfmultby0b(temp[2, i]) ^ (int)gfmultby0d(temp[3, i]));

                this.State[2, i] = (byte)((int)gfmultby0d(temp[0, i]) ^ (int)gfmultby09(temp[1, i]) ^
                 (int)gfmultby0e(temp[2, i]) ^ (int)gfmultby0b(temp[3, i]));

                this.State[3, i] = (byte)((int)gfmultby0b(temp[0, i]) ^ (int)gfmultby0d(temp[1, i]) ^
                 (int)gfmultby09(temp[2, i]) ^ (int)gfmultby0e(temp[3, i]));
            }
        }

        private static byte gfmultby01(byte b)
        {
            return b;
        }

        private static byte gfmultby02(byte b)
        {
            if (b < 0x80)
                return (byte)(int)(b << 1);
            else
                return (byte)((int)(b << 1) ^ (int)(0x1b));
        }

        private static byte gfmultby03(byte b)
        {
            return (byte)((int)gfmultby02(b) ^ (int)b);
        }

        private static byte gfmultby09(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)b);
        }

        private static byte gfmultby0b(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)gfmultby02(b) ^ (int)b);
        }

        private static byte gfmultby0d(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)gfmultby02(gfmultby02(b)) ^ (int)(b));
        }

        private static byte gfmultby0e(byte b)
        {
            return (byte)((int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)gfmultby02(gfmultby02(b)) ^ (int)gfmultby02(b));
        }

        private void setNbNkNr(Keysize keysize)
        {
            this.Nb = 4;
            switch (keysize)
            {
                case Keysize.Bits128: this.Nk = 4; this.Nr = 10; break;
                case Keysize.Bits192: this.Nk = 6; this.Nr = 12; break;
                case Keysize.Bits256: this.Nk = 8; this.Nr = 14; break;
                default: break;
            }
        }

        private void BuildSbox()
        {
            this.Sbox = new byte[16, 16]
            {
               /*******0*****1*****2*****3*****4*****5*****6*****7*****8*****9*****A*****B*****C*****D*****E*****F**/
               /*0*/ {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
               /*1*/ {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
               /*2*/ {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
               /*3*/ {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
               /*4*/ {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
               /*5*/ {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
               /*6*/ {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
               /*7*/ {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
               /*8*/ {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
               /*9*/ {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
               /*A*/ {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
               /*B*/ {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
               /*C*/ {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
               /*D*/ {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
               /*E*/ {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
               /*F*/ {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
            };
        }

        private void BuildInvSbox()
        {
            this.iSbox = new byte[16, 16]
            {
                /*******0*****1*****2*****3*****4*****5*****6*****7*****8*****9*****A*****B*****C*****D*****E*****F**/
                /*0*/ {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                /*1*/ {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                /*2*/ {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                /*3*/ {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                /*4*/ {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                /*5*/ {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                /*6*/ {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                /*7*/ {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                /*8*/ {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                /*9*/ {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                /*A*/ {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                /*B*/ {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                /*C*/ {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                /*D*/ {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                /*E*/ {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                /*F*/ {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
            };
        }

        private void BulidRcon()
        {
            this.Rcon = new byte[11, 4]
            {
                {0x00, 0x00, 0x00, 0x00},
                {0x01, 0x00, 0x00, 0x00},
                {0x02, 0x00, 0x00, 0x00},
                {0x04, 0x00, 0x00, 0x00},
                {0x08, 0x00, 0x00, 0x00},
                {0x10, 0x00, 0x00, 0x00},
                {0x20, 0x00, 0x00, 0x00},
                {0x40, 0x00, 0x00, 0x00},
                {0x80, 0x00, 0x00, 0x00},
                {0x1b, 0x00, 0x00, 0x00},
                {0x36, 0x00, 0x00, 0x00},
            };
        }

        private void KeyExpansion()
        {
            this.w = new byte[Nb * (Nr + 1), 4];

            for (int i = 0; i < Nk; i++)
            {
                this.w[i, 0] = this.key[4 * i];
                this.w[i, 1] = this.key[4 * i + 1];
                this.w[i, 2] = this.key[4 * i + 2];
                this.w[i, 3] = this.key[4 * i + 3];
            }

            byte[] temp = new byte[4];

            for (int i = Nk; i < Nb * (Nr + 1); i++)
            {
                temp[0] = this.w[i - 1, 0];
                temp[1] = this.w[i - 1, 1];
                temp[2] = this.w[i - 1, 2];
                temp[3] = this.w[i - 1, 3];

                if (i % Nk == 0)
                {
                    temp = SubWord(RotWord(temp));
                    temp[0] = (byte)((int)temp[0] ^ (int)this.Rcon[i / Nk, 0]);
                    temp[1] = (byte)((int)temp[1] ^ (int)this.Rcon[i / Nk, 1]);
                    temp[2] = (byte)((int)temp[2] ^ (int)this.Rcon[i / Nk, 2]);
                    temp[3] = (byte)((int)temp[3] ^ (int)this.Rcon[i / Nk, 3]);
                }
                else if (Nk == 8 && (i % Nk == 4))
                {
                    temp = SubWord(temp);
                }

                this.w[i, 0] = (byte)((int)this.w[i - Nk, 0] ^ (int)temp[0]);
                this.w[i, 1] = (byte)((int)this.w[i - Nk, 1] ^ (int)temp[1]);
                this.w[i, 2] = (byte)((int)this.w[i - Nk, 2] ^ (int)temp[2]);
                this.w[i, 3] = (byte)((int)this.w[i - Nk, 3] ^ (int)temp[3]);
            }
        }

        private byte[] SubWord(byte[] word)
        {
            byte[] result = new byte[4];
            result[0] = this.Sbox[word[0] >> 4, word[0] & 0x0f];
            result[1] = this.Sbox[word[1] >> 4, word[1] & 0x0f];
            result[2] = this.Sbox[word[2] >> 4, word[2] & 0x0f];
            result[3] = this.Sbox[word[3] >> 4, word[3] & 0x0f];
            return result;
        }

        private byte[] RotWord(byte[] word)
        {
            byte[] result = new byte[4];
            result[0] = word[1];
            result[1] = word[2];
            result[2] = word[3];
            result[3] = word[0];
            return result;
        }
    }
}
