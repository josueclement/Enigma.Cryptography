using Enigma.Cryptography.PQC;
using System.Text;
using Xunit;

namespace UnitTests.PQC;

// ReSharper disable once InconsistentNaming
public class MLDsaKeyPairTests
{
    [Fact]
    public void SignAndVerify_WithGeneratedKeyPair_Dsa44()
    {
        var service = new MLDsaServiceFactory().CreateDsa44Service();
        var keyPair = service.GenerateKeyPair();

        var data = Encoding.UTF8.GetBytes("ML-DSA-44 test message");
        var signature = service.Sign(data, keyPair.Private);
        var isValid = service.Verify(data, signature, keyPair.Public);

        Assert.True(isValid);
    }

    [Fact]
    public void SignAndVerify_WithGeneratedKeyPair_Dsa65()
    {
        var service = new MLDsaServiceFactory().CreateDsa65Service();
        var keyPair = service.GenerateKeyPair();

        var data = Encoding.UTF8.GetBytes("ML-DSA-65 test message");
        var signature = service.Sign(data, keyPair.Private);
        var isValid = service.Verify(data, signature, keyPair.Public);

        Assert.True(isValid);
    }

    [Fact]
    public void SignAndVerify_WithGeneratedKeyPair_Dsa87()
    {
        var service = new MLDsaServiceFactory().CreateDsa87Service();
        var keyPair = service.GenerateKeyPair();

        var data = Encoding.UTF8.GetBytes("ML-DSA-87 test message");
        var signature = service.Sign(data, keyPair.Private);
        var isValid = service.Verify(data, signature, keyPair.Public);

        Assert.True(isValid);
    }

    [Fact]
    public void SignAndVerify_Deterministic()
    {
        var service = new MLDsaServiceFactory().CreateDsa44Service(deterministic: true);
        var keyPair = service.GenerateKeyPair();

        var data = Encoding.UTF8.GetBytes("Deterministic signing test");
        var sig1 = service.Sign(data, keyPair.Private);
        var sig2 = service.Sign(data, keyPair.Private);

        Assert.Equal(sig1, sig2);
        Assert.True(service.Verify(data, sig1, keyPair.Public));
    }
}
