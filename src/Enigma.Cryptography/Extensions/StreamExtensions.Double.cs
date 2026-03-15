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
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write double
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteDoubleAsync(double value)
        {
            var data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
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
            StreamReadHelpers.ReadExact(stream, buffer, 0, sizeof(double));
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
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
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, sizeof(double)).ConfigureAwait(false);
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return BitConverter.ToDouble(buffer, 0);
        }
    }
}
