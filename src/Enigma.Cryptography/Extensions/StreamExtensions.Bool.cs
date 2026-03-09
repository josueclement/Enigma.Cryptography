using System;
using System.IO;
using System.Threading.Tasks;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Bool stream extensions
/// </summary>
public static class StreamExtensionsBool
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write bool value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteBool(bool value)
        {
            var data = BitConverter.GetBytes(value);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write bool value
        /// </summary>
        /// <param name="value">Value</param>
        public async Task WriteBoolAsync(bool value)
        {
            var data = BitConverter.GetBytes(value);
            await stream.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
        }

        /// <summary>
        /// Read bool value
        /// </summary>
        /// <returns>Bool value</returns>
        /// <exception cref="IOException"></exception>
        public bool ReadBool()
        {
            var buffer = new byte[sizeof(bool)];
            if (stream.Read(buffer, 0, sizeof(bool)) != sizeof(bool))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToBoolean(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read bool value
        /// </summary>
        /// <returns>Bool value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<bool> ReadBoolAsync()
        {
            var buffer = new byte[sizeof(bool)];
            if (await stream.ReadAsync(buffer, 0, sizeof(bool)).ConfigureAwait(false) != sizeof(bool))
                throw new IOException("Incorrect number of bytes read");
            return BitConverter.ToBoolean(buffer, 0);
        }
    }
}