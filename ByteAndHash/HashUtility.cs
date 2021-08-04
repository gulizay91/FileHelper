using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ByteAndHash
{
    /// <summary>
    /// Defines the <see cref="HashUtility" />.
    /// </summary>
    public static class HashUtility
    {
        #region Methods

        /// <summary>
        /// The ComputeMD5Hash.
        /// </summary>
        /// <param name="data">The data<see cref="byte[]"/>.</param>
        /// <returns>The <see cref="string"/>.</returns>
        public static string ComputeMD5Hash(byte[] data)
        {
            using (var md5 = new MD5CryptoServiceProvider())
            {
                var buffer = md5.ComputeHash(data);
                var sb = new StringBuilder();
                for (int i = 0; i < buffer.Length; i++)
                {
                    //To force the hex string to upper-case
                    sb.Append(buffer[i].ToString("X2"));
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// The ComputeMD5Hash.
        /// </summary>
        /// <param name="input">The input<see cref="string"/>.</param>
        /// <returns>The <see cref="string"/>.</returns>
        public static string ComputeMD5Hash(string input)
        {
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            return ComputeMD5Hash(inputBytes);
        }

        /// <summary>
        /// The ComputeSHA256Hash.
        /// </summary>
        /// <param name="data">The data<see cref="byte[]"/>.</param>
        /// <returns>The <see cref="string"/>.</returns>
        public static string ComputeSHA256Hash(byte[] data)
        {
            return BitConverter.ToString(SHA256.Create().ComputeHash(data)).Replace("-", "").ToLower();
        }

        /// <summary>
        /// The Hash.
        /// </summary>
        /// <param name="text">The text<see cref="string"/>.</param>
        /// <returns>The <see cref="string"/>.</returns>
        public static string Hash(string text)
        {
            var rng = new SequentialRandomNumberGenerator();
            var prf = KeyDerivationPrf.HMACSHA256;
            var iterationCount = 10000;
            var saltSize = 128 / 8;
            var numBytesRequested = 256 / 8;

            byte[] salt = new byte[saltSize];
            rng.GetBytes(salt);
            byte[] subkey = KeyDerivation.Pbkdf2(text, salt, prf, iterationCount, numBytesRequested);

            var outputBytes = new byte[13 + salt.Length + subkey.Length];
            outputBytes[0] = 0x01; // format marker
            WriteNetworkByteOrder(outputBytes, 1, (uint)prf);
            WriteNetworkByteOrder(outputBytes, 5, (uint)iterationCount);
            WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);
            Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
            Buffer.BlockCopy(subkey, 0, outputBytes, 13 + saltSize, subkey.Length);

            return Convert.ToBase64String(outputBytes);
        }

        /// <summary>
        /// The HashMD5.
        /// </summary>
        /// <param name="text">The text<see cref="string"/>.</param>
        /// <returns>The <see cref="string"/>.</returns>
        public static string HashMD5(string text)
        {
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(text);
            byte[] hash = md5.ComputeHash(inputBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
            }
            return sb.ToString();
        }

        /// <summary>
        /// The ComputeSha256Hash.
        /// </summary>
        /// <param name="rawData">The rawData<see cref="string"/>.</param>
        /// <returns>The <see cref="string"/>.</returns>
        public static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256   
            using SHA256 sha256Hash = SHA256.Create();
            // ComputeHash - returns byte array  
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

            // Convert byte array to a string   
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }

        /// <summary>
        /// The WriteNetworkByteOrder.
        /// </summary>
        /// <param name="buffer">The buffer<see cref="byte[]"/>.</param>
        /// <param name="offset">The offset<see cref="int"/>.</param>
        /// <param name="value">The value<see cref="uint"/>.</param>
        private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
        {
            buffer[offset + 0] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)(value >> 0);
        }

        #endregion

        /// <summary>
        /// Defines the <see cref="SequentialRandomNumberGenerator" />.
        /// </summary>
        private sealed class SequentialRandomNumberGenerator : RandomNumberGenerator
        {
            #region Fields

            /// <summary>
            /// Defines the _value.
            /// </summary>
            private byte _value;

            #endregion

            #region Methods

            /// <summary>
            /// The GetBytes.
            /// </summary>
            /// <param name="data">The data<see cref="byte[]"/>.</param>
            public override void GetBytes(byte[] data)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] = _value++;
                }
            }

            #endregion
        }
    }
}
