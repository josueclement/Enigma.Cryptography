using Enigma.Cryptography.DataEncoding;
using Enigma.Cryptography.Hash;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests.Hash;

public class Sha1Tests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvTest(byte[] data, byte[] expectedHash)
    {
        var service = new HashServiceFactory().CreateSha1Service();
        
        using var input = new MemoryStream(data);
        var hash = await service.HashAsync(input, cancellationToken: TestContext.Current.CancellationToken);
        
        Assert.Equal(expectedHash, hash);
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(Path.Combine("Hash", "sha1.csv"))
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // data
                    hex.Decode(values[1]) // expected hash
                };
            });
    }
}