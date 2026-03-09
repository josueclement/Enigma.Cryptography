using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Int64 stream extensions
/// </summary>
public static class StreamExtensionsInt64
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteLong(long value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteLongAsync(long value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int64 value
        /// </summary>
        /// <returns>Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public long ReadLong()
        {
            var buffer = new byte[sizeof(long)];
            if (stream.Read(buffer, 0, sizeof(long)) != sizeof(long))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToInt64(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read Int64 value
        /// </summary>
        /// <returns>Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<long> ReadLongAsync()
        {
            var buffer = new byte[sizeof(long)];
            if (await stream.ReadAsync(buffer, 0, sizeof(long)).ConfigureAwait(false) != sizeof(long))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToInt64(buffer, 0);
        }

        /// <summary>
        /// Write unsigned Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteULong(ulong value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write unsigned Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteULongAsync(ulong value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read unsigned Int64 value
        /// </summary>
        /// <returns>Unsigned Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public ulong ReadULong()
        {
            var buffer = new byte[sizeof(ulong)];
            if (stream.Read(buffer, 0, sizeof(ulong)) != sizeof(ulong))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToUInt64(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read unsigned Int64 value
        /// </summary>
        /// <returns>Unsigned Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<ulong> ReadULongAsync()
        {
            var buffer = new byte[sizeof(ulong)];
            if (await stream.ReadAsync(buffer, 0, sizeof(ulong)).ConfigureAwait(false) != sizeof(ulong))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToUInt64(buffer, 0);
        }
    }
}