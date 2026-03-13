using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests.BlockCiphers;

public class AdditionalEngineTests
{
    private static async Task RoundTrip(
        IBlockCipherService service,
        byte[] key,
        byte[] iv,
        byte[] plaintext)
    {
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);

        byte[] encryptedBytes;
        using (var msInput = new MemoryStream(plaintext))
        using (var msEncrypted = new MemoryStream())
        {
            await service.EncryptAsync(msInput, msEncrypted, parameters);
            encryptedBytes = msEncrypted.ToArray();
        }

        using var msEncInput = new MemoryStream(encryptedBytes);
        using var msDecrypted = new MemoryStream();
        await service.DecryptAsync(msEncInput, msDecrypted, parameters);

        Assert.Equal(plaintext, msDecrypted.ToArray());
    }

    [Fact]
    public async Task Twofish_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateTwofishEngine);
        var key = RandomUtils.GenerateRandomBytes(32); // 256-bit
        var iv = RandomUtils.GenerateRandomBytes(16);  // 128-bit block
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }

    [Fact]
    public async Task Serpent_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateSerpentEngine);
        var key = RandomUtils.GenerateRandomBytes(32);
        var iv = RandomUtils.GenerateRandomBytes(16);
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }

    [Fact]
    public async Task Camellia_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateCamelliaEngine);
        var key = RandomUtils.GenerateRandomBytes(32);
        var iv = RandomUtils.GenerateRandomBytes(16);
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }

    [Fact]
    public async Task Cast5_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateCast5Engine);
        var key = RandomUtils.GenerateRandomBytes(16); // 128-bit
        var iv = RandomUtils.GenerateRandomBytes(8);   // 64-bit block
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }

    [Fact]
    public async Task Idea_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateIdeaEngine);
        var key = RandomUtils.GenerateRandomBytes(16); // 128-bit
        var iv = RandomUtils.GenerateRandomBytes(8);   // 64-bit block
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }

    [Fact]
    public async Task Seed_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateSeedEngine);
        var key = RandomUtils.GenerateRandomBytes(16); // 128-bit
        var iv = RandomUtils.GenerateRandomBytes(16);  // 128-bit block
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }

    [Fact]
    public async Task Aria_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAriaEngine);
        var key = RandomUtils.GenerateRandomBytes(32);
        var iv = RandomUtils.GenerateRandomBytes(16);
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }

    [Fact]
    public async Task Sm4_Cbc_RoundTrip()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateSm4Engine);
        var key = RandomUtils.GenerateRandomBytes(16); // 128-bit
        var iv = RandomUtils.GenerateRandomBytes(16);  // 128-bit block
        var plaintext = RandomUtils.GenerateRandomBytes(64);
        await RoundTrip(service, key, iv, plaintext);
    }
}
