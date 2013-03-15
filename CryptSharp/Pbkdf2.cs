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
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using BtcAddress.Properties;

namespace BtcAddress.CryptSharp {
    public class Pbkdf2 : Stream {
        #region PBKDF2
        public delegate void ComputeHmacCallback(byte[] key, byte[] data, byte[] output);

        byte[] _key;
        private readonly byte[] _salt;
        byte[] _saltBuf;
        byte[] _block;
        byte[] _blockT1;
        byte[] _blockT2;
        ComputeHmacCallback _computeHmacCallback;
        int _iterations;

        public Pbkdf2(byte[] key, byte[] salt, int iterations,
            ComputeHmacCallback computeHmacCallback, int hmacLength)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (salt == null) throw new ArgumentNullException("salt");
            _key = key;
            _salt = salt;
            _iterations = iterations;
            if (computeHmacCallback != null) Reopen(key, salt, iterations, computeHmacCallback, hmacLength);
        }

        static void Clear(Array arr)
        {
            if (arr == null) throw new ArgumentNullException("arr");
            Array.Clear(arr, 0, arr.Length);
        }

        public void Read(byte[] output) {
            if (output == null) throw new ArgumentNullException("output");
            Helper.CheckNull("output", output);

            var bytes = Read(output, 0, output.Length);
            if (bytes < output.Length) {
                throw new ArgumentException(Resources.Pbkdf2_Read_Can_only_return_
                    + output.Length.ToString() + Resources.Pbkdf2_Read__bytes_, "output");
            }
        }

        public static void ComputeKey(byte[] key, byte[] salt, int iterations,
            ComputeHmacCallback computeHmacCallback, int hmacLength, byte[] output)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (salt == null) throw new ArgumentNullException("salt");
            if (computeHmacCallback == null) throw new ArgumentNullException("computeHmacCallback");
            if (output == null) throw new ArgumentNullException("output");
            using (var kdf = new Pbkdf2
                (key, salt, iterations, computeHmacCallback, hmacLength)) {
                kdf.Read(output);
            }
        }

        public static ComputeHmacCallback CallbackFromHmac<T>() where T : KeyedHashAlgorithm, new() {
            return (key, data, output) =>
                {
                    T hmac;
                    using (hmac = new T())
                    {
                        if (key != null) Helper.CheckNull("key", key);
                        if (data != null) Helper.CheckNull("data", data);
                        if (key != null) hmac.Key = key;
                        if (data != null)
                        {
                            var hmacOutput = hmac.ComputeHash(data);

                            try
                            {
                                if (output != null)
                                {
                                    Helper.CheckRange("output", output, hmacOutput.Length, hmacOutput.Length);
                                    Array.Copy(hmacOutput, output, output.Length);
                                }
                            }
                            finally
                            {
                                Clear(hmacOutput);
                            }
                        }
                    }
                };
        }

        public void Reopen(byte[] key, byte[] salt, int iterations,
            ComputeHmacCallback computeHmacCallback, int hmacLength) {
            if (key == null) throw new ArgumentNullException("key");
            if (salt == null) throw new ArgumentNullException("salt");
            if (computeHmacCallback == null) throw new ArgumentNullException("computeHmacCallback");
            Helper.CheckNull("key", key);
            Helper.CheckNull("salt", salt);
            Helper.CheckNull("computeHmacCallback", computeHmacCallback);
            Helper.CheckRange("salt", salt, 0, int.MaxValue - 4);
            Helper.CheckRange("iterations", iterations, 1, int.MaxValue);
            Helper.CheckRange("hmacLength", hmacLength, 1, int.MaxValue);
            _key = new byte[key.Length]; 
            Array.Copy(key, _key, key.Length);
            _saltBuf = new byte[salt.Length + 4]; 
            Array.Copy(salt, _saltBuf, salt.Length);
            _iterations = iterations; 
            _computeHmacCallback = computeHmacCallback;
            _block = new byte[hmacLength]; 
            _blockT1 = new byte[hmacLength]; 
            _blockT2 = new byte[hmacLength];
            ReopenStream();
        }

        public override void Close() {
            if (_key != null) Clear(_key);
            Clear(_saltBuf);
            if (_block != null) Clear(_block);
        }

        void ComputeBlock(uint pos) {
            if (_saltBuf != null)
            {
                Helper.UInt32ToBytes(pos, _saltBuf, _saltBuf.Length - 4);
                if (_blockT1 != null) ComputeHmac(_saltBuf, _blockT1);
            }
            if (_blockT1 != null)
            {
                if (_block != null)
                {
                    Array.Copy(_blockT1, _block, _blockT1.Length);

                    for (var i = 1; i < _iterations; i++) {
                        if (_blockT2 != null)
                        {
                            ComputeHmac(_blockT1, _blockT2); // let's not require aliasing support
                            Array.Copy(_blockT2, _blockT1, _blockT2.Length);
                        }
                        for (var j = 0; j < _block.Length; j++) {
                            if (_block.Length > j) _block[j] ^= _blockT1[j];
                        }
                    }
                }

                Clear(_blockT1);
            }
            if (_blockT2 != null) Clear(_blockT2);
        }

        void ComputeHmac(byte[] data, byte[] output)
        {
            Debug.Assert(data == null || output == null);
            if (_computeHmacCallback != null) if (_key != null)
                if (data != null) _computeHmacCallback(_key, data, output);
        }

        #endregion

        #region Stream
        long _blockStart;
        long _blockEnd;
        long _pos;

        void ReopenStream() {
            _blockStart = _blockEnd = _pos = 0;
        }

        public override void Flush() 
        {

        }

        public override int Read(byte[] buffer, int offset, int count) {
            if (buffer == null) throw new ArgumentNullException("buffer");
            Helper.CheckBounds("buffer", buffer, offset, count); 
            var bytes = 0;

            while (count > 0) {
                if (Position < _blockStart || Position >= _blockEnd) {
                    if (Position >= Length) break;

                    if (_block != null)
                    {
                        var pos = Position / _block.Length;
                        ComputeBlock((uint)(pos + 1));
                        _blockStart = pos * _block.Length;
                    }
                    _blockEnd = _blockStart + _block.Length;
                }

                var bytesSoFar = (int)(Position - _blockStart);
                var bytesThisTime = Math.Min(_block.Length - bytesSoFar, count);
                Array.Copy(_block, bytesSoFar, buffer, bytes, bytesThisTime);
                count -= bytesThisTime; bytes += bytesThisTime; Position += bytesThisTime;
            }

            return bytes;
        }

        public override long Seek(long offset, SeekOrigin origin) {
            long pos;

            switch (origin) {
                case SeekOrigin.Begin: pos = offset; break;
                case SeekOrigin.Current: pos = Position + offset; break;
                case SeekOrigin.End: pos = Length + offset; break;
                default: throw new ArgumentException(Resources.Pbkdf2_Seek_Unknown_seek_type_, "origin");
            }

            if (pos < 0) { throw new ArgumentException(Resources.Pbkdf2_Seek_Seeking_before_the_stream_start_, "offset"); }
            Position = pos; 
            return pos;
        }

        public override void SetLength(long value) {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException("buffer");
            throw new NotSupportedException();
        }

        public override bool CanRead {
            get { return true; }
        }

        public override bool CanSeek {
            get { return true; }
        }

        public override bool CanWrite {
            get { return false; }
        }

        public override long Length {
            get { return _block.Length * uint.MaxValue; }
        }

        public override long Position {
            get { return _pos; }
            set {
                if (_pos < 0) { throw new ArgumentOutOfRangeException("value"); }
                _pos = value;
            }
        }
        #endregion
    }
}
