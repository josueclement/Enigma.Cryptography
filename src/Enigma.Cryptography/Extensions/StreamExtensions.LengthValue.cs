using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Length-Value stream extensions
/// </summary>
public static class StreamExtensionsLengthValue
{
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
        /// <returns>Value</returns>
        public byte[] ReadLengthValue()
        {
            var length = stream.ReadInt();
            return stream.ReadBytes(length);
        }

        /// <summary>
        /// Asynchronously read value length and value
        /// </summary>
        /// <returns>Value</returns>
        public async Task<byte[]> ReadLengthValueAsync()
        {
            var length = await stream.ReadIntAsync().ConfigureAwait(false);
            return await stream.ReadBytesAsync(length).ConfigureAwait(false);
        }
    }
}