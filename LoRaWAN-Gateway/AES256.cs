using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LoRaWAN_Gateway
{
    /// <summary>
    /// Service for AES cryptography.
    /// </summary>
    public class AesCryptographyService
    {
               /// <summary>
        /// Encrypts data using AES algorithm.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <returns>The encrypted data.</returns>
        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            // Create an instance of AES algorithm.
            using (var aes = Aes.Create())
            {
                // Set the size of the encryption key in bits. 
                aes.KeySize = 128;

                // Set the block size in bits. 
                aes.BlockSize = 128;

                // Specify the padding mode used in the encryption algorithm. 
                // PaddingMode.Zeros appends zeros to the end of the data to ensure it fills the last block.
                aes.Padding = PaddingMode.Zeros;

                // Set the encryption key and initialization vector.
                aes.Key = key;
                aes.IV = iv;

                // Create an encryptor object using the encryption key and initialization vector.
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    // Perform the encryption operation and return the encrypted data.
                    return PerformCryptography(data, encryptor);
                }
            }
        }

        /// <summary>
        /// Decrypts data using AES algorithm.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="key">The decryption key.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <returns>The decrypted data.</returns>
        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            // Create an instance of AES algorithm.
            using (var aes = Aes.Create())
            {
                // Set the size of the encryption key in bits. 
                aes.KeySize = 128;

                // Set the block size in bits. 
                aes.BlockSize = 128;

                // Specify the padding mode used in the encryption algorithm. 
                // PaddingMode.Zeros appends zeros to the end of the data to ensure it fills the last block.
                aes.Padding = PaddingMode.Zeros;

                // Set the decryption key and initialization vector.
                aes.Key = key;
                aes.IV = iv;

                // Create a decryptor object using the decryption key and initialization vector.
                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    // Perform the decryption operation and return the decrypted data.
                    return PerformCryptography(data, decryptor);
                }
            }
        }

        /// <summary>
        /// Performs cryptographic transformation.
        /// </summary>
        /// <param name="data">The data to be transformed.</param>
        /// <param name="cryptoTransform">The cryptographic transformation to apply.</param>
        /// <returns>The transformed data.</returns>
        private byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            // Create a memory stream to hold the transformed data.
            using (var ms = new MemoryStream())
            {
                // Create a CryptoStream object with the memory stream and cryptographic transformation.
                using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                {
                    // Write the data to the CryptoStream, transforming it in the process.
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                }

                // Return the transformed data as a byte array.
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Calculates Message Integrity Code (MIC) using HMAC-SHA256 algorithm.
        /// </summary>
        /// <param name="data">The data to calculate MIC for.</param>
        /// <param name="key">The key for HMAC.</param>
        /// <returns>The calculated MIC.</returns>
        public byte[] CalculateMIC(byte[] data, byte[] key)
        {
            // Create an instance of HMAC-SHA256 algorithm with the provided key.
            using (var hmac = new HMACSHA256(key))
            {
                // Compute the hash of the data using HMAC-SHA256 algorithm.
                return hmac.ComputeHash(data);
            }
        }
    }
}
