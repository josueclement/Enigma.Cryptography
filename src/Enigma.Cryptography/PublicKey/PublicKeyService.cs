using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;

namespace Enigma.Cryptography.PublicKey;

/// <summary>
/// Provides cryptographic operations for asymmetric (public-key) encryption, decryption,
/// digital signatures, and key pair generation using the BouncyCastle library.
/// </summary>
/// <param name="cipherFactory">Factory method that creates the asymmetric block cipher implementation</param>
/// <param name="keyPairGeneratorFactory">Factory method that creates the key pair generator implementation</param>
/// <param name="signerFactory">Factory method that creates the digital signature implementation</param>
public class PublicKeyService(
    Func<IAsymmetricBlockCipher> cipherFactory,
    Func<IAsymmetricCipherKeyPairGenerator> keyPairGeneratorFactory,
    Func<ISigner> signerFactory) : IPublicKeyService
{
    /// <inheritdoc />
    public AsymmetricCipherKeyPair GenerateKeyPair(int keySize)
    {
        var generator = keyPairGeneratorFactory();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySize));
        return generator.GenerateKeyPair();
    }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] data, AsymmetricKeyParameter publicKey)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (publicKey is null) throw new ArgumentNullException(nameof(publicKey));

        var cipher = cipherFactory();
        cipher.Init(forEncryption: true, publicKey);
        return cipher.ProcessBlock(data, 0, data.Length);
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] data, AsymmetricKeyParameter privateKey)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        var cipher = cipherFactory();
        cipher.Init(forEncryption: false, privateKey);
        return cipher.ProcessBlock(data, 0, data.Length);
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        var signer = signerFactory();
        signer.Init(forSigning: true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    /// <inheritdoc />
    public bool Verify(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (signature is null) throw new ArgumentNullException(nameof(signature));
        if (publicKey is null) throw new ArgumentNullException(nameof(publicKey));

        var signer = signerFactory();
        signer.Init(forSigning: false, publicKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }
}
