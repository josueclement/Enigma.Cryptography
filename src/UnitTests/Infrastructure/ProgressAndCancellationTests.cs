using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.Hash;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace UnitTests.Infrastructure;

/// <summary>
/// Synchronous IProgress implementation that collects values inline.
/// </summary>
internal class SyncProgress<T>(Action<T> handler) : IProgress<T>
{
    public void Report(T value) => handler(value);
}

public class ProgressAndCancellationTests
{
    [Fact]
    public async Task Hash_ReportsProgress()
    {
        var service = new HashService(() => new Sha256Digest());
        var data = RandomUtils.GenerateRandomBytes(8192);
        using var input = new MemoryStream(data);

        var reported = new List<int>();
        var progress = new SyncProgress<int>(bytes => reported.Add(bytes));

        await service.HashAsync(input, progress, cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotEmpty(reported);
    }

    [Fact]
    public async Task BlockCipher_ReportsProgress()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);

        var key = RandomUtils.GenerateRandomBytes(32);
        var iv = RandomUtils.GenerateRandomBytes(16);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);

        var data = RandomUtils.GenerateRandomBytes(8192);
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();

        var reported = new List<int>();
        var progress = new SyncProgress<int>(bytes => reported.Add(bytes));

        await service.EncryptAsync(input, output, parameters, progress, cancellationToken: TestContext.Current.CancellationToken);

        Assert.NotEmpty(reported);
    }

    [Fact]
    public async Task Hash_PreCancelledToken_Throws()
    {
        var service = new HashService(() => new Sha256Digest());
        using var input = new MemoryStream(new byte[] { 1, 2, 3 });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            service.HashAsync(input, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task BlockCipher_PreCancelledToken_Throws()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);

        var key = RandomUtils.GenerateRandomBytes(32);
        var iv = RandomUtils.GenerateRandomBytes(16);
        var parameters = new ParametersWithIV(new KeyParameter(key), iv);

        using var input = new MemoryStream(new byte[] { 1, 2, 3 });
        using var output = new MemoryStream();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            service.EncryptAsync(input, output, parameters, cancellationToken: cts.Token));
    }
}
