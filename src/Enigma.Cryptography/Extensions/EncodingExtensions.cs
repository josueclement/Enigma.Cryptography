using System.Text;
using Enigma.Cryptography.DataEncoding;

namespace Enigma.Cryptography.Extensions;

/// <summary>
/// Encoding extensions
/// </summary>
public static class EncodingExtensions
{
    private static readonly Base64Service Base64Service = new();
    private static readonly HexService HexService = new();
    private static readonly Encoding DefaultEncoding = Encoding.Default;

    /// <summary>
    /// Bytes extensions (byte[])
    /// </summary>
    /// <param name="bytes">Bytes</param>
    extension(byte[] bytes)
    {
        /// <summary>
        /// Encode bytes to base64 string
        /// </summary>
        /// <returns>Base64 string</returns>
        public string ToBase64String()
            => Base64Service.Encode(bytes);

        /// <summary>
        /// Encode bytes to hex string
        /// </summary>
        /// <returns>Hex string</returns>
        public string ToHexString()
            => HexService.Encode(bytes);
        
        /// <summary>
        /// Decodes all the bytes in the specified byte array into a string
        /// </summary>
        /// <param name="encoding">Encoding. If null, Encoding.Default will be used</param>
        /// <returns>String</returns>
        // ReSharper disable once MemberCanBePrivate.Global
        public string GetString(Encoding? encoding = null)
            => (encoding ?? DefaultEncoding).GetString(bytes);
        
        /// <summary>
        /// Decodes all the bytes in the specified byte array into a string with UTF-8 encoding
        /// </summary>
        /// <returns>String</returns>
        public string GetUtf8String()
            => GetString(bytes, Encoding.UTF8);
    
        /// <summary>
        /// Decodes all the bytes in the specified byte array into a string with ASCII encoding
        /// </summary>
        /// <returns>String</returns>
        public string GetAsciiString()
            => GetString(bytes, Encoding.ASCII);
    }

    /// <summary>
    /// String extensions
    /// </summary>
    /// <param name="str">String</param>
    extension(string str)
    {
        /// <summary>
        /// Decode base64 string to bytes
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] FromBase64String()
            => Base64Service.Decode(str);
    
        /// <summary>
        /// Decode hex string to bytes
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] FromHexString()
            => HexService.Decode(str);
    
        /// <summary>
        /// Encodes all the characters in the specified string into a sequence of bytes
        /// </summary>
        /// <param name="encoding">Encoding. If null, Encoding.Default will be used</param>
        /// <returns>Bytes</returns>
        // ReSharper disable once MemberCanBePrivate.Global
        public byte[] GetBytes(Encoding? encoding = null)
            => (encoding ?? DefaultEncoding).GetBytes(str);
    
        /// <summary>
        /// Encodes all the characters in the specified string into a sequence of bytes with UTF-8 encoding
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] GetUtf8Bytes()
            => GetBytes(str, Encoding.UTF8);
    
        /// <summary>
        /// Encodes all the characters in the specified string into a sequence of bytes with ASCII encoding
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] GetAsciiBytes()
            => GetBytes(str, Encoding.ASCII);
    }
}