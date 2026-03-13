using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Tag-Length-Value stream extensions
/// </summary>
public static class StreamExtensionsTagLengthValue
{
    private const int DefaultMaxLength = 10 * 1024 * 1024; // 10 MB

    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write Tag-Length-Value
        /// </summary>
        /// <param name="tag">Tag</param>
        /// <param name="value">Value</param>
        public void WriteTagLengthValue(ushort tag, byte[] value)
        {
            stream.WriteUShort(tag);
            stream.WriteLengthValue(value);
        }

        /// <summary>
        /// Asynchronously write Tag-Length-Value
        /// </summary>
        /// <param name="tag">Tag</param>
        /// <param name="value">Value</param>
        public async Task WriteTagLengthValueAsync(ushort tag, byte[] value)
        {
            await stream.WriteUShortAsync(tag).ConfigureAwait(false);
            await stream.WriteLengthValueAsync(value).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Tag-Length-Value
        /// </summary>
        /// <param name="maxLength">Maximum allowed length in bytes (default 10 MB)</param>
        /// <returns>(Tag, Value)</returns>
        public (ushort tag, byte[] value) ReadTagLengthValue(int maxLength = DefaultMaxLength)
        {
            var tag = stream.ReadUShort();
            var value = stream.ReadLengthValue(maxLength);
            return (tag, value);
        }

        /// <summary>
        /// Asynchronously read Tag-Length-Value
        /// </summary>
        /// <param name="maxLength">Maximum allowed length in bytes (default 10 MB)</param>
        /// <returns>(Tag, Value)</returns>
        public async Task<(ushort tag, byte[] value)> ReadTagLengthValueAsync(int maxLength = DefaultMaxLength)
        {
            var tag = await stream.ReadUShortAsync().ConfigureAwait(false);
            var value = await stream.ReadLengthValueAsync(maxLength).ConfigureAwait(false);
            return (tag, value);
        }
    }
}
