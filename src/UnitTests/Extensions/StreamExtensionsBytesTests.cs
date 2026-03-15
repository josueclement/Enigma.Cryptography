using Enigma.Cryptography.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests.Extensions;

public class StreamExtensionsBytesTests
{
    [Fact]
    public void ReadWriteByte()
    {
        using var output = new MemoryStream();
        output.WriteByte(byte.MaxValue);
        output.WriteByte(byte.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadByte();
        Assert.Equal(byte.MaxValue, result);
        result = input.ReadByte();
        Assert.Equal(byte.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteByteAsync()
    {
        using var output = new MemoryStream();
        await output.WriteByteAsync(byte.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteByteAsync(byte.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadByteAsync(TestContext.Current.CancellationToken);
        Assert.Equal(byte.MaxValue, result);
        result = await input.ReadByteAsync(TestContext.Current.CancellationToken);
        Assert.Equal(byte.MinValue, result);
    }

    [Fact]
    public void ReadWriteBytes()
    {
        using var output = new MemoryStream();
        output.WriteBytes([0, 1, 254, 255]);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadBytes(4);
        Assert.Equal([0, 1, 254, 255], result);
    }

    [Fact]
    public async Task ReadWriteBytesAsync()
    {
        using var output = new MemoryStream();
        await output.WriteBytesAsync([0, 1, 254, 255], TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadBytesAsync(4, TestContext.Current.CancellationToken);
        Assert.Equal([0, 1, 254, 255], result);
    }
}
