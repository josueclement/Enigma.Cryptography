using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Int32 stream extensions
/// </summary>
public static class StreamExtensionsInt32
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteInt(int value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteIntAsync(int value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int32 value
        /// </summary>
        /// <returns>Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public int ReadInt()
        {
            var buffer = new byte[sizeof(int)];
            if (stream.Read(buffer, 0, sizeof(int)) != sizeof(int))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToInt32(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read Int32 value
        /// </summary>
        /// <returns>Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<int> ReadIntAsync()
        {
            var buffer = new byte[sizeof(int)];
            if (await stream.ReadAsync(buffer, 0, sizeof(int)).ConfigureAwait(false) != sizeof(int))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToInt32(buffer, 0);
        }

        /// <summary>
        /// Write unsigned Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteUInt(uint value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write unsigned Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteUIntAsync(uint value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read unsigned Int32 value
        /// </summary>
        /// <returns>Unsigned Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public uint ReadUInt()
        {
            var buffer = new byte[sizeof(uint)];
            if (stream.Read(buffer, 0, sizeof(uint)) != sizeof(uint))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToUInt32(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read unsigned Int32 value
        /// </summary>
        /// <returns>Unsigned Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<uint> ReadUIntAsync()
        {
            var buffer = new byte[sizeof(uint)];
            if (await stream.ReadAsync(buffer, 0, sizeof(uint)).ConfigureAwait(false) != sizeof(uint))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToUInt32(buffer, 0);
        }
    }
}