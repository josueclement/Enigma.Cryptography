using Enigma.Cryptography.PQC;
using Xunit;

namespace UnitTests.PQC;

// ReSharper disable once InconsistentNaming
public class MLKemKeyPairTests
{
    [Fact]
    public void EncapsulateDecapsulate_WithGeneratedKeyPair_Kem512()
    {
        var service = new MLKemServiceFactory().CreateKem512();
        var keyPair = service.GenerateKeyPair();

        var (encapsulation, secret) = service.Encapsulate(keyPair.Public);
        var recovered = service.Decapsulate(encapsulation, keyPair.Private);

        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void EncapsulateDecapsulate_WithGeneratedKeyPair_Kem768()
    {
        var service = new MLKemServiceFactory().CreateKem768();
        var keyPair = service.GenerateKeyPair();

        var (encapsulation, secret) = service.Encapsulate(keyPair.Public);
        var recovered = service.Decapsulate(encapsulation, keyPair.Private);

        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void EncapsulateDecapsulate_WithGeneratedKeyPair_Kem1024()
    {
        var service = new MLKemServiceFactory().CreateKem1024();
        var keyPair = service.GenerateKeyPair();

        var (encapsulation, secret) = service.Encapsulate(keyPair.Public);
        var recovered = service.Decapsulate(encapsulation, keyPair.Private);

        Assert.Equal(secret, recovered);
    }
}
