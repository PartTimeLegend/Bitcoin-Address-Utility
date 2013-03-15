#region License
/*
Illusory Studios C# Crypto Library (CryptSharp)
Copyright (c) 2011 James F. Bellinger <jfb@zer7.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#endregion

using System;
using System.Security.Cryptography;
using System.Threading;
using BtcAddress.Properties;
using CryptSharp.Utility;

namespace BtcAddress.CryptSharp {
    // See http://www.tarsnap.com/scrypt/scrypt.pdf for algorithm details.
    // TODO: Test on a big-endian machine and make sure it works.
    // TODO: Feel hatred for whatever genius decided C# wouldn't have 'safe'
    //       stack-allocated arrays. He has stricken ugliness upon a thousand codes.
    public static class SCrypt {
        const int HLen = 32;
        static readonly Pbkdf2.ComputeHmacCallback HmacCallback =
            Pbkdf2.CallbackFromHmac<HMACSHA256>();

        public static void ComputeKey(byte[] key, byte[] salt,
            int cost, int blockSize, int parallel, int? maxThreads, byte[] output)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (salt == null) throw new ArgumentNullException("salt");
            if (maxThreads == null) throw new ArgumentNullException("maxThreads");
            if (output == null) throw new ArgumentNullException("output");
            using (var kdf = GetStream(key, salt, cost, blockSize, parallel, maxThreads))
            {
                kdf.Read(output);
            }
        }

        public static byte[] GetEffectivePbkdf2Salt(byte[] key, byte[] salt,
            int cost, int blockSize, int parallel, int? maxThreads) {
            if (key == null) throw new ArgumentNullException("key");
            if (salt == null) throw new ArgumentNullException("salt");
            if (maxThreads == null) throw new ArgumentNullException("maxThreads");
            Helper.CheckNull("key", key); 
            Helper.CheckNull("salt", salt);
            return MFcrypt(key, salt, cost, blockSize, parallel, maxThreads);
        }

        public static Pbkdf2 GetStream(byte[] key, byte[] salt,
            int cost, int blockSize, int parallel, int? maxThreads) {
            if (key == null) throw new ArgumentNullException("key");
            if (salt == null) throw new ArgumentNullException("salt");
            if (maxThreads == null) throw new ArgumentNullException("maxThreads");
            var b = GetEffectivePbkdf2Salt(key, salt, cost, blockSize, parallel, maxThreads);
            if (HmacCallback != null)
            {
                if (b != null)
                {
                    var kdf = new Pbkdf2(key, b, 1, HmacCallback, HLen);
                    Clear(b); 
                    return kdf;
                }
            }
            }

        static void Clear(Array arr)
        {
            if (arr != null) Array.Clear(arr, 0, arr.Length);
        }

        static byte[] MFcrypt(byte[] P, byte[] S,
            int cost, int blockSize, int parallel, int? maxThreads) {
            if (P == null) throw new ArgumentNullException("P");
            if (S == null) throw new ArgumentNullException("S");
            var mfLen = blockSize * 128;
            if (maxThreads == null)
            {
                maxThreads = int.MaxValue;
            }

            if (cost <= 0 || (cost & (cost - 1)) != 0)
            {
                throw new ArgumentOutOfRangeException("cost", Resources.SCrypt_MFcrypt_Cost_must_be_a_positive_power_of_2_);
            }
            Helper.CheckRange("blockSize", blockSize, 1, int.MaxValue / 32);
            Helper.CheckRange("parallel", parallel, 1, int.MaxValue / mfLen);
            Helper.CheckRange("maxThreads", (int)maxThreads, 1, int.MaxValue);

            var b = new byte[parallel * mfLen];
            if (HmacCallback != null) Pbkdf2.ComputeKey(P, S, 1, HmacCallback, HLen, b);

            var b0 = new uint[b.Length / 4];
            for (var i = 0; i < b0.Length; i++)
            {
                if (b0.Length > i) b0[i] = Helper.BytesToUInt32Le(b, i * 4);
            } // code is easier with uint[]
            ThreadSMixCalls(b0, mfLen, cost, blockSize, parallel, (int)maxThreads);
            for (int i = 0; i < b0.Length; i++)
            {
                if (b0.Length > i) Helper.UInt32ToBytesLe(b0[i], b, i * 4);
            }
            Clear(b0);

            return b;
        }

        static void ThreadSMixCalls(uint[] b0, int mfLen,
            int cost, int blockSize, int parallel, int maxThreads) {
            if (b0 == null) throw new ArgumentNullException("b0");
            var current = 0;
            ThreadStart workerThread = () =>
                {
                    while (true)
                    {
                        var j = Interlocked.Increment(ref current) - 1;
                        if (j < parallel)
                        {
                            if (b0 != null) SMix(b0, j*mfLen/4, b0, j*mfLen/4, (uint) cost, blockSize);
                        }
                        else
                        {
                            break;
                        }
                    }
                };

            var threadCount = Math.Max(1, Math.Min(Environment.ProcessorCount, Math.Min(maxThreads, parallel)));
            var threads = new Thread[threadCount - 1];
            for (var i = 0; i < threads.Length; i++)
            {
                if (threads.Length > i) (threads[i] = new Thread(workerThread, 8192)).Start();
            }
            workerThread();
            for (var i = 0; i < threads.Length; i++)
            {
                if (threads.Length > i) threads[i].Join();
            }
        }

        static void SMix(uint[] b, int boffset, uint[] bp, int bpoffset, uint n, int r) {
            if (b == null) throw new ArgumentNullException("b");
            if (bp == null) throw new ArgumentNullException("bp");
            var nmask = n - 1; 
            var bs = 16 * 2 * r;
            var scratch1 = new uint[16];
            var scratch2 = new uint[16];
            var scratchX = new uint[16];
            var scratchY = new uint[bs];
            var scratchZ = new uint[bs];

            var x = new uint[bs]; 
            var v = new uint[n][];
            for (var i = 0; i < v.Length; i++)
            {
                if (v.Length > i) v[i] = new uint[bs];
            }

            Array.Copy(b, boffset, x, 0, bs);
            for (uint i = 0; i < n; i++)
            {
                if (v.Length > i) Array.Copy(x, v[i], bs);
                BlockMix(x, 0, x, 0, scratchX, scratchY, scratch1, scratch2, r);
            }
            for (var i = 0; i < n; i++) 
            {
                if (x.Length > bs - 16)
                {
                    var j = x[bs - 16] & nmask;
                    if (v.Length > j)
                    {
                        var vj = v[j];
                        for (var k = 0; k < scratchZ.Length; k++)
                        {
                            if (x.Length > k) scratchZ[k] = x[k] ^ vj[k];
                        }
                    }
                }
                BlockMix(scratchZ, 0, x, 0, scratchX, scratchY, scratch1, scratch2, r);
            }
            Array.Copy(x, 0, bp, bpoffset, bs);

            for (var i = 0; i < v.Length; i++)
            {
                if (v.Length > i) Clear(v[i]);
            }
            Clear(v); 
            Clear(x);
            Clear(scratchX); 
            Clear(scratchY); 
            Clear(scratchZ);
            Clear(scratch1); 
            Clear(scratch2);
        }

        static void BlockMix
            (uint[] b,        // 16*2*r
             int boffset,
             uint[] bp,       // 16*2*r
             int bpoffset,
             uint[] x,        // 16
             uint[] y,        // 16*2*r -- unnecessary but it allows us to alias B and Bp
             uint[] scratch1, // 16
             uint[] scratch2, // 16
             int r) {
            if (b == null) throw new ArgumentNullException("b");
            if (bp == null) throw new ArgumentNullException("bp");
            if (x == null) throw new ArgumentNullException("x");
            if (y == null) throw new ArgumentNullException("y");
            if (scratch1 == null) throw new ArgumentNullException("scratch1");
            if (scratch2 == null) throw new ArgumentNullException("scratch2");
            int k = boffset;
            int m = 0;
            int n = 16 * r;
            Array.Copy(b, (2 * r - 1) * 16, x, 0, 16);

            for (var i = 0; i < r; i++) 
            {
                for (var j = 0; j < scratch1.Length; j++)
                {
                    if (scratch1.Length > j) if (b.Length > j + k) scratch1[j] = x[j] ^ b[j + k];
                }
                Salsa20Core.Compute(8, scratch1, 0, x, 0, scratch2);
                Array.Copy(x, 0, y, m, 16);
                k += 16;

                for (var j = 0; j < scratch1.Length; j++)
                {
                    if (scratch1.Length > j) if (scratch1.Length > j)
                        if (scratch1.Length > j) if (b.Length > j + k) scratch1[j] = x[j] ^ b[j + k];
                }
                Salsa20Core.Compute(8, scratch1, 0, x, 0, scratch2);
                Array.Copy(x, 0, y, m + n, 16);
                k += 16;

                m += 16;
            }

            Array.Copy(y, 0, bp, bpoffset, y.Length);
        }
    }
}
