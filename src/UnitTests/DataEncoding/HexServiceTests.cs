using Enigma.Cryptography.DataEncoding;
using Xunit;

namespace UnitTests.DataEncoding;

public class HexServiceTests
{
    private readonly HexService _service = new();

    [Fact]
    public void RoundTrip()
    {
        var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var encoded = _service.Encode(data);
        var decoded = _service.Decode(encoded);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void KnownVector()
    {
        var data = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
        var encoded = _service.Encode(data);
        Assert.Equal("48656c6c6f", encoded);
    }

    [Fact]
    public void EmptyInput()
    {
        var encoded = _service.Encode([]);
        var decoded = _service.Decode(encoded);
        Assert.Empty(decoded);
    }
}
