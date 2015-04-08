using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Security.Cryptography;
using AES;

namespace Test
{
    /// <summary>
    /// 
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            byte[] IV = Convert.FromBase64String("54bRC9RGKfFxZMbk67B1Ow==");

            byte[] Key = new byte[32]{0xAB,0xDD,0x4E,0x18,0xF4,0xC2,0x82,0xA2,
                                      0xCF,0xDB,0x98,0x74,0x2B,0x53,0x1D,0x02,
                                      0x92,0x0F,0x98,0x3B,0x34,0x3B,0xFF,0xBA,
                                      0xA4,0x67,0x28,0x1D,0xC9,0xB5,0x70,0x41};

            int bufsize = 65536;     

            AESProvider aes = new AESProvider(Key, IV);
            string s = Console.ReadLine();
            byte[] c = aes.Encrypt(s);
            byte[] ob = Encoding.UTF8.GetBytes(s);
            byte[] c2 = aes.EncryptFinalBlock(ob, 0, ob.Length);

            Console.WriteLine(Convert.ToBase64String(c));
            Console.WriteLine(Convert.ToBase64String(c2));
            string s2 = aes.Decrypt(c);

            byte[] sb = aes.DecryptFinalBlock(c2, 0, c2.Length);
            string s3 = Encoding.UTF8.GetString(sb);

            Console.WriteLine(s2);
            Console.WriteLine(s == s2);
            Console.WriteLine(s3);
            Console.WriteLine(s3 == s);

            FileStream orfile = new FileStream("1.tif", FileMode.Open, FileAccess.Read);
            FileStream ofile = new FileStream("2.cli", FileMode.Create, FileAccess.ReadWrite);
            FileStream ffile = new FileStream("3.tif", FileMode.Create, FileAccess.Write);
            int len;
            byte[] buffer = new byte[bufsize];
            Stopwatch watch = new Stopwatch();
            watch.Start();
            while ((len = orfile.Read(buffer, 0, bufsize)) > 0)
            {
                byte[] enc;
                if (orfile.Position < orfile.Length)
                {
                    enc=aes.EncryptBlock(buffer, 0, len);
                }
                else
                {
                    enc=aes.EncryptFinalBlock(buffer, 0, len);
                }
                ofile.Write(enc, 0, enc.Length);
            }
            watch.Stop();
            Console.WriteLine(watch.Elapsed);

            ofile.Seek(0, SeekOrigin.Begin);

            watch.Restart();
            while ((len = ofile.Read(buffer, 0, bufsize)) > 0)
            {
                byte[] dec;
                if (ofile.Position < ofile.Length)
                {
                    dec = aes.DecryptBlock(buffer, 0, len);
                }
                else
                {
                    dec = aes.DecryptFinalBlock(buffer, 0, len);
                }
                ffile.Write(dec, 0, dec.Length);
            }
            watch.Stop();
            Console.WriteLine(watch.Elapsed);

            orfile.Close();
            ofile.Close();
            ffile.Close();
            Console.ReadKey(true);
        }
    }
}
