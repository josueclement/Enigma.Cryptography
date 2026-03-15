using System;

namespace Enigma.Cryptography.Padding;

/// <summary>
/// No padding service
/// </summary>
public class NoPaddingService : IPaddingService
{
    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return data;
    }

    /// <inheritdoc />
    public byte[] Unpad(byte[] data, int blockSize)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return data;
    }
}
