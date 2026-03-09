using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Bytes stream extensions
/// </summary>
public static class StreamExtensionsBytes
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write byte value
        /// </summary>
        /// <param name="value">Byte value</param>
        public void WriteByte(byte value)
            => stream.Write([value], 0, 1);

        /// <summary>
        /// Asynchronously write byte value
        /// </summary>
        /// <param name="value">Byte value</param>
        public async Task WriteByteAsync(byte value)
            => await stream.WriteAsync([value], 0, 1).ConfigureAwait(false);

        /// <summary>
        /// Read byte value
        /// </summary>
        /// <returns>Byte value</returns>
        /// <exception cref="IOException"></exception>
        public byte ReadByte()
        {
            var buffer = new byte[sizeof(byte)];
            if (stream.Read(buffer, 0, sizeof(byte)) != sizeof(byte))
                throw new IOException("Incorrect number of bytes read");
            return buffer[0];
        }

        /// <summary>
        /// Asynchronously read byte value
        /// </summary>
        /// <returns>Byte value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<byte> ReadByteAsync()
        {
            var buffer = new byte[sizeof(byte)];
            if (await stream.ReadAsync(buffer, 0, sizeof(byte)).ConfigureAwait(false) != sizeof(byte))
                throw new IOException("Incorrect number of bytes read");
            return buffer[0];
        }

        /// <summary>
        /// Write bytes
        /// </summary>
        /// <param name="bytes">Bytes</param>
        public void WriteBytes(byte[] bytes)
            => stream.Write(bytes, 0, bytes.Length);

        /// <summary>
        /// Asynchronously write bytes
        /// </summary>
        /// <param name="bytes">Bytes</param>
        public async Task WriteBytesAsync(byte[] bytes)
            => await stream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);

        /// <summary>
        /// Read bytes
        /// </summary>
        /// <param name="count">Number of bytes to read</param>
        /// <returns>Bytes</returns>
        /// <exception cref="IOException"></exception>
        public byte[] ReadBytes(int count)
        {
            var buffer = new byte[count];
            if (stream.Read(buffer, 0, count) != count)
                throw new IOException("Incorrect number of bytes read");
            return buffer;
        }

        /// <summary>
        /// Asynchronously read bytes
        /// </summary>
        /// <param name="count">Number of bytes to read</param>
        /// <returns>Bytes</returns>
        /// <exception cref="IOException"></exception>
        public async Task<byte[]> ReadBytesAsync(int count)
        {
            var buffer = new byte[count];
            if (await stream.ReadAsync(buffer, 0, count).ConfigureAwait(false) != count)
                throw new IOException("Incorrect number of bytes read");
            return buffer;
        }
    }
}