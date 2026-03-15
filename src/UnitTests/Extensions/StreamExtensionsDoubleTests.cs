using Enigma.Cryptography.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests.Extensions;

public class StreamExtensionsDoubleTests
{
    [Fact]
    public void ReadWriteDouble()
    {
        using var output = new MemoryStream();
        output.WriteDouble(double.MaxValue);
        output.WriteDouble(double.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadDouble();
        Assert.Equal(double.MaxValue, result);
        result = input.ReadDouble();
        Assert.Equal(double.MinValue, result);
    }

    [Fact]
    public async Task ReadWriteDoubleAsync()
    {
        using var output = new MemoryStream();
        await output.WriteDoubleAsync(double.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteDoubleAsync(double.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadDoubleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(double.MaxValue, result);
        result = await input.ReadDoubleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(double.MinValue, result);
    }
}
