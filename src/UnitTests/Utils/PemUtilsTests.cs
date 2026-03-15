using System.IO;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Xunit;

namespace UnitTests.Utils;

public class PemUtilsTests
{
    [Fact]
    public void SaveKey_LoadKey_RoundTrip()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        using var ms = new MemoryStream();
        PemUtils.SaveKey(keyPair.Public, ms);

        ms.Position = 0;
        var loaded = PemUtils.LoadKey(ms);

        Assert.Equal(keyPair.Public, loaded);
    }

    [Fact]
    public void SavePrivateKey_LoadPrivateKey_RoundTrip()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        using var ms = new MemoryStream();
        PemUtils.SavePrivateKey(keyPair.Private, ms, "testpassword123");

        ms.Position = 0;
        var loaded = PemUtils.LoadPrivateKey(ms, "testpassword123");

        Assert.Equal(keyPair.Private, loaded);
    }

    [Fact]
    public void SaveKey_DoesNotDisposeStream()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        using var ms = new MemoryStream();
        PemUtils.SaveKey(keyPair.Public, ms);

        // Stream should still be usable after SaveKey
        Assert.True(ms.CanWrite);
        Assert.True(ms.CanRead);
        ms.Position = 0;
        Assert.True(ms.Length > 0);
    }

    [Fact]
    public void SavePrivateKey_DoesNotDisposeStream()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        using var ms = new MemoryStream();
        PemUtils.SavePrivateKey(keyPair.Private, ms, "test");

        // Stream should still be usable after SavePrivateKey
        Assert.True(ms.CanWrite);
        Assert.True(ms.CanRead);
        ms.Position = 0;
        Assert.True(ms.Length > 0);
    }

    [Fact]
    public void LoadKey_DoesNotDisposeStream()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        using var ms = new MemoryStream();
        PemUtils.SaveKey(keyPair.Public, ms);
        ms.Position = 0;

        PemUtils.LoadKey(ms);

        // Stream should still be usable after LoadKey
        Assert.True(ms.CanRead);
    }

    [Fact]
    public void LoadPrivateKey_DoesNotDisposeStream()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);

        using var ms = new MemoryStream();
        PemUtils.SavePrivateKey(keyPair.Private, ms, "test");
        ms.Position = 0;

        PemUtils.LoadPrivateKey(ms, "test");

        // Stream should still be usable after LoadPrivateKey
        Assert.True(ms.CanRead);
    }
}
