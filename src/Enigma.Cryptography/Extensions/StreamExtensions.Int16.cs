using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Int16 stream extensions
/// </summary>
public static class StreamExtensionsInt16
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteShort(short value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteShortAsync(short value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int16 value
        /// </summary>
        /// <returns>Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public short ReadShort()
        {
            var buffer = new byte[sizeof(short)];
            if (stream.Read(buffer, 0, sizeof(short)) != sizeof(short))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToInt16(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read Int16 value
        /// </summary>
        /// <returns>Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<short> ReadShortAsync()
        {
            var buffer = new byte[sizeof(short)];
            if (await stream.ReadAsync(buffer, 0, sizeof(short)).ConfigureAwait(false) != sizeof(short))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToInt16(buffer, 0);
        }

        /// <summary>
        /// Write unsigned Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteUShort(ushort value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write unsigned Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteUShortAsync(ushort value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read unsigned Int16 value
        /// </summary>
        /// <returns>Unsigned Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public ushort ReadUShort()
        {
            var buffer = new byte[sizeof(ushort)];
            if (stream.Read(buffer, 0, sizeof(ushort)) != sizeof(ushort))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToUInt16(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read unsigned Int16 value
        /// </summary>
        /// <returns>Unsigned Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<ushort> ReadUShortAsync()
        {
            var buffer = new byte[sizeof(ushort)];
            if (await stream.ReadAsync(buffer, 0, sizeof(ushort)).ConfigureAwait(false) != sizeof(ushort))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToUInt16(buffer, 0);
        }
    }
}