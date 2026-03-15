using Enigma.Cryptography.DataEncoding;
using Xunit;

namespace UnitTests.DataEncoding;

public class Base64ServiceTests
{
    private readonly Base64Service _service = new();

    [Fact]
    public void RoundTrip()
    {
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var encoded = _service.Encode(data);
        var decoded = _service.Decode(encoded);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void KnownVector()
    {
        var data = "Hello, World!"u8.ToArray();
        var encoded = _service.Encode(data);
        Assert.Equal("SGVsbG8sIFdvcmxkIQ==", encoded);
    }

    [Fact]
    public void EmptyInput()
    {
        var encoded = _service.Encode([]);
        var decoded = _service.Decode(encoded);
        Assert.Empty(decoded);
    }
}
