using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;

namespace Enigma.Cryptography.PQC;

/// <summary>
/// Provides implementation for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA), a post-quantum cryptographic signing scheme.
/// </summary>
/// <remarks>
/// This service offers key generation, message signing, and signature verification operations using the ML-DSA algorithm.
/// The implementation uses BouncyCastle's cryptographic libraries and allows configurable parameters through a factory pattern.
/// ML-DSA is designed to be secure against quantum computer attacks, unlike traditional public-key algorithms.
/// </remarks>
/// <param name="parametersFactory">Factory function that provides algorithm-specific parameters for the ML-DSA operations</param>
/// <param name="deterministic">Whether to use deterministic signing. Default is false.</param>
// ReSharper disable once InconsistentNaming
public class MLDsaService(
    Func<MLDsaParameters> parametersFactory,
    bool deterministic = false) : IMLDsaService
{
    /// <inheritdoc />
    public AsymmetricCipherKeyPair GenerateKeyPair()
    {
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), parametersFactory()));
        return generator.GenerateKeyPair();
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data, AsymmetricKeyParameter privateKey)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        var signer = new MLDsaSigner(parametersFactory(), deterministic);
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

        var signer = new MLDsaSigner(parametersFactory(), deterministic);
        signer.Init(forSigning: false, publicKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }
}
