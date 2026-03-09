using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Float stream extensions
/// </summary>
public static class StreamExtensionsFloat
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write float value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteFloat(float value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }
    
        /// <summary>
        /// Asynchronously write float value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteFloatAsync(float value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }
    
        /// <summary>
        /// Read float value
        /// </summary>
        /// <returns>Float value</returns>
        /// <exception cref="IOException"></exception>
        public float ReadFloat()
        {
            var buffer = new byte[sizeof(float)];
            if (stream.Read(buffer, 0, sizeof(float)) != sizeof(float))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToSingle(buffer, 0);
        }
    
        /// <summary>
        /// Asynchronously read float value
        /// </summary>
        /// <returns>Float value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<float> ReadFloatAsync()
        {
            var buffer = new byte[sizeof(float)];
            if (await stream.ReadAsync(buffer, 0, sizeof(float)).ConfigureAwait(false) != sizeof(float))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToSingle(buffer, 0);
        }
    }
}