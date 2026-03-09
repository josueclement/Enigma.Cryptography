using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Double stream extensions
/// </summary>
public static class StreamExtensionsDouble
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write double
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteDouble(double value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }
    
        /// <summary>
        /// Asynchronously write double
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteDoubleAsync(double value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read double value
        /// </summary>
        /// <returns>Double value</returns>
        /// <exception cref="IOException"></exception>
        public double ReadDouble()
        {
            var buffer = new byte[sizeof(double)];
            if (stream.Read(buffer, 0, sizeof(double)) != sizeof(double))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToDouble(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read double value
        /// </summary>
        /// <returns>Double value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<double> ReadDoubleAsync()
        {
            var buffer = new byte[sizeof(double)];
            if (await stream.ReadAsync(buffer, 0, sizeof(double)).ConfigureAwait(false) != sizeof(double))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToDouble(buffer, 0);
        }
    }
}