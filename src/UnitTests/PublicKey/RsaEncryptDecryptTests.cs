using Enigma.Cryptography.PublicKey;
using System.Text;
using Xunit;

namespace UnitTests.PublicKey;

public class RsaEncryptDecryptTests
{
    [Fact]
    public void GenerateKeyPair_Returns_Valid_2048Bit_KeyPair()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        Assert.NotNull(keyPair);
        Assert.NotNull(keyPair.Public);
        Assert.NotNull(keyPair.Private);
        Assert.False(keyPair.Public.IsPrivate);
        Assert.True(keyPair.Private.IsPrivate);
    }

    [Fact]
    public void EncryptDecrypt_RoundTrip_WithGeneratedKeyPair()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        var plaintext = Encoding.UTF8.GetBytes("Hello, RSA round-trip!");
        var encrypted = service.Encrypt(plaintext, keyPair.Public);
        var decrypted = service.Decrypt(encrypted, keyPair.Private);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void SignVerify_RoundTrip_WithGeneratedKeyPair()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        var data = Encoding.UTF8.GetBytes("Data to sign and verify");
        var signature = service.Sign(data, keyPair.Private);
        var isValid = service.Verify(data, signature, keyPair.Public);

        Assert.True(isValid);
    }
}
