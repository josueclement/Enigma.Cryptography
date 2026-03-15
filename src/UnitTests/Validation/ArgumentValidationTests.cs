using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Cryptography.BlockCiphers;
using Enigma.Cryptography.DataEncoding;
using Enigma.Cryptography.Extensions;
using Enigma.Cryptography.Hash;
using Enigma.Cryptography.KDF;
using Enigma.Cryptography.Padding;
using Enigma.Cryptography.PQC;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.StreamCiphers;
using Enigma.Cryptography.Utils;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace UnitTests.Validation;

public class ArgumentValidationTests
{
    // S5 - RandomUtils
    [Fact]
    public void RandomUtils_ZeroSize_Throws()
        => Assert.Throws<ArgumentException>(() => RandomUtils.GenerateRandomBytes(0));

    [Fact]
    public void RandomUtils_NegativeSize_Throws()
        => Assert.Throws<ArgumentException>(() => RandomUtils.GenerateRandomBytes(-1));

    // S5 - Pbkdf2Service
    [Fact]
    public void Pbkdf2_NullPassword_Throws()
        => Assert.Throws<ArgumentNullException>(() => new Pbkdf2Service().GenerateKey(32, null!, new byte[16]));

    [Fact]
    public void Pbkdf2_NullSalt_Throws()
        => Assert.Throws<ArgumentNullException>(() => new Pbkdf2Service().GenerateKey(32, "pass", null!));

    [Fact]
    public void Pbkdf2_ZeroSize_Throws()
        => Assert.Throws<ArgumentException>(() => new Pbkdf2Service().GenerateKey(0, "pass", new byte[16]));

    [Fact]
    public void Pbkdf2_ZeroIterations_Throws()
        => Assert.Throws<ArgumentException>(() => new Pbkdf2Service().GenerateKey(32, "pass", new byte[16], 0));

    // S5 - Argon2Service
    [Fact]
    public void Argon2_NullPasswordBytes_Throws()
        => Assert.Throws<ArgumentNullException>(() => new Argon2Service().GenerateKey(32, null!, new byte[16]));

    [Fact]
    public void Argon2_NullSalt_Throws()
        => Assert.Throws<ArgumentNullException>(() => new Argon2Service().GenerateKey(32, new byte[8], null!));

    [Fact]
    public void Argon2_ZeroSize_Throws()
        => Assert.Throws<ArgumentException>(() => new Argon2Service().GenerateKey(0, new byte[8], new byte[16]));

    // S5 - Base64Service
    [Fact]
    public void Base64_EncodeNull_Throws()
        => Assert.Throws<ArgumentNullException>(() => new Base64Service().Encode(null!));

    [Fact]
    public void Base64_DecodeNull_Throws()
        => Assert.Throws<ArgumentNullException>(() => new Base64Service().Decode(null!));

    // S5 - HexService
    [Fact]
    public void Hex_EncodeNull_Throws()
        => Assert.Throws<ArgumentNullException>(() => new HexService().Encode(null!));

    [Fact]
    public void Hex_DecodeNull_Throws()
        => Assert.Throws<ArgumentNullException>(() => new HexService().Decode(null!));

    // S5 - PaddingService
    [Fact]
    public void Padding_PadNullData_Throws()
    {
        var service = new PaddingServiceFactory().CreatePkcs7Service();
        Assert.Throws<ArgumentNullException>(() => service.Pad(null!, 16));
    }

    [Fact]
    public void Padding_UnpadNullData_Throws()
    {
        var service = new PaddingServiceFactory().CreatePkcs7Service();
        Assert.Throws<ArgumentNullException>(() => service.Unpad(null!, 16));
    }

    // S5 - NoPaddingService
    [Fact]
    public void NoPadding_PadNullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => new NoPaddingService().Pad(null!, 16));

    [Fact]
    public void NoPadding_UnpadNullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => new NoPaddingService().Unpad(null!, 16));

    // S5 - HashService
    [Fact]
    public async Task Hash_NullInput_Throws()
    {
        var service = new HashService(() => new Sha256Digest());
        await Assert.ThrowsAsync<ArgumentNullException>(() => service.HashAsync(null!, cancellationToken: TestContext.Current.CancellationToken));
    }

    // S5 - BlockCipherService
    [Fact]
    public async Task BlockCipher_EncryptNullInput_Throws()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);
        var parameters = new ParametersWithIV(new KeyParameter(new byte[32]), new byte[16]);
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.EncryptAsync(null!, new MemoryStream(), parameters, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task BlockCipher_EncryptNullOutput_Throws()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);
        var parameters = new ParametersWithIV(new KeyParameter(new byte[32]), new byte[16]);
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.EncryptAsync(new MemoryStream(), null!, parameters, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task BlockCipher_EncryptNullParameters_Throws()
    {
        var engineFactory = new BlockCipherEngineFactory();
        var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.EncryptAsync(new MemoryStream(), new MemoryStream(), null!, cancellationToken: TestContext.Current.CancellationToken));
    }

    // S5 - StreamCipherService
    [Fact]
    public async Task StreamCipher_EncryptNullKey_Throws()
    {
        var factory = new StreamCipherServiceFactory();
        var service = factory.CreateChaCha20Service();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.EncryptAsync(new MemoryStream(), new MemoryStream(), null!, new byte[8], cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task StreamCipher_EncryptNullNonce_Throws()
    {
        var factory = new StreamCipherServiceFactory();
        var service = factory.CreateChaCha20Service();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            service.EncryptAsync(new MemoryStream(), new MemoryStream(), new byte[32], null!, cancellationToken: TestContext.Current.CancellationToken));
    }

    // S5 - PublicKeyService
    [Fact]
    public void PublicKey_EncryptNullData_Throws()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);
        Assert.Throws<ArgumentNullException>(() => service.Encrypt(null!, keyPair.Public));
    }

    [Fact]
    public void PublicKey_EncryptNullKey_Throws()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        Assert.Throws<ArgumentNullException>(() => service.Encrypt(new byte[] { 1 }, null!));
    }

    // S5 - MLDsaService
    [Fact]
    public void MLDsa_SignNullData_Throws()
    {
        var service = new MLDsaServiceFactory().CreateDsa44Service();
        var keyPair = service.GenerateKeyPair();
        Assert.Throws<ArgumentNullException>(() => service.Sign(null!, keyPair.Private));
    }

    [Fact]
    public void MLDsa_SignNullKey_Throws()
    {
        var service = new MLDsaServiceFactory().CreateDsa44Service();
        Assert.Throws<ArgumentNullException>(() => service.Sign(new byte[] { 1 }, null!));
    }

    [Fact]
    public void MLDsa_VerifyNullSignature_Throws()
    {
        var service = new MLDsaServiceFactory().CreateDsa44Service();
        var keyPair = service.GenerateKeyPair();
        Assert.Throws<ArgumentNullException>(() => service.Verify(new byte[] { 1 }, null!, keyPair.Public));
    }

    // S5 - MLKemService
    [Fact]
    public void MLKem_EncapsulateNullKey_Throws()
    {
        var service = new MLKemServiceFactory().CreateKem512();
        Assert.Throws<ArgumentNullException>(() => service.Encapsulate(null!));
    }

    [Fact]
    public void MLKem_DecapsulateNullEncapsulation_Throws()
    {
        var service = new MLKemServiceFactory().CreateKem512();
        var keyPair = service.GenerateKeyPair();
        Assert.Throws<ArgumentNullException>(() => service.Decapsulate(null!, keyPair.Private));
    }

    [Fact]
    public void MLKem_DecapsulateNullKey_Throws()
    {
        var service = new MLKemServiceFactory().CreateKem512();
        Assert.Throws<ArgumentNullException>(() => service.Decapsulate(new byte[100], null!));
    }

    // S5 - PemUtils
    [Fact]
    public void PemUtils_SaveKeyNullKey_Throws()
        => Assert.Throws<ArgumentNullException>(() => PemUtils.SaveKey(null!, new MemoryStream()));

    [Fact]
    public void PemUtils_SaveKeyNullOutput_Throws()
    {
        var service = new PublicKeyServiceFactory().CreateRsaService();
        var keyPair = service.GenerateKeyPair(2048);
        Assert.Throws<ArgumentNullException>(() => PemUtils.SaveKey(keyPair.Public, null!));
    }

    [Fact]
    public void PemUtils_LoadKeyNullInput_Throws()
        => Assert.Throws<ArgumentNullException>(() => PemUtils.LoadKey(null!));

    [Fact]
    public void PemUtils_LoadPrivateKeyNullInput_Throws()
        => Assert.Throws<ArgumentNullException>(() => PemUtils.LoadPrivateKey(null!, "password"));

    [Fact]
    public void PemUtils_LoadPrivateKeyNullPassword_Throws()
        => Assert.Throws<ArgumentNullException>(() => PemUtils.LoadPrivateKey(new MemoryStream(), null!));

    // S4 - ReadLengthValue max length
    [Fact]
    public void ReadLengthValue_ExceedsMaxLength_Throws()
    {
        using var ms = new MemoryStream();
        // Write a length value of 100 bytes
        ms.WriteInt(100);
        ms.Position = 0;
        // But set max to 50
        Assert.Throws<InvalidOperationException>(() => ms.ReadLengthValue(maxLength: 50));
    }

    [Fact]
    public void ReadLengthValue_NegativeLength_Throws()
    {
        using var ms = new MemoryStream();
        ms.WriteInt(-5);
        ms.Position = 0;
        Assert.Throws<InvalidOperationException>(() => ms.ReadLengthValue());
    }
}
