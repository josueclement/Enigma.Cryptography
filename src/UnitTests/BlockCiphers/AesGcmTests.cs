using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.DataEncoding;
using Org.BouncyCastle.Crypto;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace UnitTests.BlockCiphers;

public class AesGcmTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvEncryptTest(byte[] key, byte[] iv, byte[] data, byte[] encrypted)
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateGcmService(engineFactory.CreateAesEngine);
        var parameters = new BlockCipherParametersFactory().CreateGcmParameters(key, iv);
        
        using var msInput = new MemoryStream(data);
        using var msOutput = new MemoryStream();

        await service.EncryptAsync(msInput, msOutput, parameters, cancellationToken: TestContext.Current.CancellationToken);
        
        Assert.Equal(encrypted, msOutput.ToArray());
    }
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public async Task CsvDecryptTest(byte[] key, byte[] iv, byte[] data, byte[] encrypted)
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateGcmService(engineFactory.CreateAesEngine);
        var parameters = new BlockCipherParametersFactory().CreateGcmParameters(key, iv);
        
        using var msInput = new MemoryStream(encrypted);
        using var msOutput = new MemoryStream();

        await service.DecryptAsync(msInput, msOutput, parameters, cancellationToken: TestContext.Current.CancellationToken);
        
        Assert.Equal(data, msOutput.ToArray()); 
    }
    
    [Fact]
    public async Task TamperedCiphertextThrowsOnDecrypt()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateGcmService(engineFactory.CreateAesEngine);
        var key = new byte[16]; // 128-bit zero key
        var iv = new byte[12]; // 96-bit zero nonce
        var parameters = new BlockCipherParametersFactory().CreateGcmParameters(key, iv);
        var plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        // Encrypt the data
        using var msInput = new MemoryStream(plaintext);
        using var msEncrypted = new MemoryStream();
        await service.EncryptAsync(msInput, msEncrypted, parameters, cancellationToken: TestContext.Current.CancellationToken);

        // Tamper with the ciphertext by flipping a byte
        var tampered = msEncrypted.ToArray();
        tampered[0] ^= 0xFF;

        // Decrypting tampered ciphertext must fail authentication
        using var msTampered = new MemoryStream(tampered);
        using var msOutput = new MemoryStream();
        await Assert.ThrowsAsync<InvalidCipherTextException>(() =>
            service.DecryptAsync(msTampered, msOutput, parameters, cancellationToken: TestContext.Current.CancellationToken));
    }

    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(Path.Combine("BlockCiphers", "aes-gcm.csv"))
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // key
                    hex.Decode(values[1]), // iv
                    hex.Decode(values[2]), // data
                    hex.Decode(values[3]) // encrypted
                };
            });
    }
}