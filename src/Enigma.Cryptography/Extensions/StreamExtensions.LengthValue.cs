using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Length-Value stream extensions
/// </summary>
public static class StreamExtensionsLengthValue
{
    private const int DefaultMaxLength = 10 * 1024 * 1024; // 10 MB

    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write value length and value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteLengthValue(byte[] value)
        {
            stream.WriteInt(value.Length);
            stream.WriteBytes(value);
        }

        /// <summary>
        /// Asynchronously write value length and value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteLengthValueAsync(byte[] value)
        {
            await stream.WriteIntAsync(value.Length).ConfigureAwait(false);
            await stream.WriteBytesAsync(value).ConfigureAwait(false);
        }

        /// <summary>
        /// Read value length and value
        /// </summary>
        /// <param name="maxLength">Maximum allowed length in bytes (default 10 MB)</param>
        /// <returns>Value</returns>
        /// <exception cref="InvalidOperationException">Thrown when length is negative or exceeds maxLength</exception>
        public byte[] ReadLengthValue(int maxLength = DefaultMaxLength)
        {
            var length = stream.ReadInt();
            if (length < 0 || length > maxLength)
                throw new InvalidOperationException($"Length value {length} is out of allowed range [0, {maxLength}].");
            return stream.ReadBytes(length);
        }

        /// <summary>
        /// Asynchronously read value length and value
        /// </summary>
        /// <param name="maxLength">Maximum allowed length in bytes (default 10 MB)</param>
        /// <returns>Value</returns>
        /// <exception cref="InvalidOperationException">Thrown when length is negative or exceeds maxLength</exception>
        public async Task<byte[]> ReadLengthValueAsync(int maxLength = DefaultMaxLength)
        {
            var length = await stream.ReadIntAsync().ConfigureAwait(false);
            if (length < 0 || length > maxLength)
                throw new InvalidOperationException($"Length value {length} is out of allowed range [0, {maxLength}].");
            return await stream.ReadBytesAsync(length).ConfigureAwait(false);
        }
    }
}
