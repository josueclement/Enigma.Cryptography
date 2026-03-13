namespace Enigma.Cryptography.PQC;

/// <summary>
/// Factory interface for creating Module-Lattice-Based Digital Signature Algorithm (ML-DSA) services.
/// ML-DSA is a post-quantum cryptographic signature scheme standardized by NIST.
/// </summary>
/// <remarks>
/// ML-DSA (previously known as CRYSTALS-Dilithium) provides digital signature functionality
/// that is designed to be secure against attacks from quantum computers.
/// Different security levels (44, 65, 87) offer varying levels of security and performance trade-offs.
/// </remarks>
// ReSharper disable once InconsistentNaming
public interface IMLDsaServiceFactory
{
    /// <summary>
    /// Creates an ML-DSA signature service with security level 44 (NIST security level 2).
    /// </summary>
    /// <param name="deterministic">Whether to use deterministic signing. Default is false.</param>
    /// <returns>An implementation of <see cref="IMLDsaService"/> configured for ML-DSA-44.</returns>
    IMLDsaService CreateDsa44Service(bool deterministic = false);

    /// <summary>
    /// Creates an ML-DSA signature service with security level 65 (NIST security level 3).
    /// </summary>
    /// <param name="deterministic">Whether to use deterministic signing. Default is false.</param>
    /// <returns>An implementation of <see cref="IMLDsaService"/> configured for ML-DSA-65.</returns>
    IMLDsaService CreateDsa65Service(bool deterministic = false);

    /// <summary>
    /// Creates an ML-DSA signature service with security level 87 (NIST security level 5).
    /// </summary>
    /// <param name="deterministic">Whether to use deterministic signing. Default is false.</param>
    /// <returns>An implementation of <see cref="IMLDsaService"/> configured for ML-DSA-87.</returns>
    IMLDsaService CreateDsa87Service(bool deterministic = false);
}
