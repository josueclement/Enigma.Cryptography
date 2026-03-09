using Enigma.Cryptography.PQC;
using Enigma.Cryptography.Utils;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests.PQC;

// ReSharper disable once InconsistentNaming
public class MLKemTests
{
    [Fact]
    public async Task CheckGoodKey()
    {
        var service = new MLKemServiceFactory().CreateKem1024();
        
        var privateKeyInput = new FileStream(Path.Combine("PQC", "kem1024_A_private.pem"), FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyInput, "test1234");
        
        var encapsulation = await File.ReadAllBytesAsync(Path.Combine("PQC", "encapsulation.bin"), cancellationToken: TestContext.Current.CancellationToken);
        var secret = await File.ReadAllBytesAsync(Path.Combine("PQC", "secret.bin"), cancellationToken: TestContext.Current.CancellationToken);

        var generatedKey = service.Decapsulate(encapsulation, privateKey);
        
        Assert.Equal(secret, generatedKey);
    }
    
    [Fact]
    public async Task CheckBadKey()
    {
        var service = new MLKemServiceFactory().CreateKem1024();
        
        var privateKeyInput = new FileStream(Path.Combine("PQC", "kem1024_B_private.pem"), FileMode.Open, FileAccess.Read);
        var privateKey = PemUtils.LoadPrivateKey(privateKeyInput, "test1234");
        
        var encapsulation = await File.ReadAllBytesAsync(Path.Combine("PQC", "encapsulation.bin"), cancellationToken: TestContext.Current.CancellationToken);
        var secret = await File.ReadAllBytesAsync(Path.Combine("PQC", "secret.bin"), cancellationToken: TestContext.Current.CancellationToken);

        var generatedKey = service.Decapsulate(encapsulation, privateKey);
        
        Assert.NotEqual(secret, generatedKey);
    }
}