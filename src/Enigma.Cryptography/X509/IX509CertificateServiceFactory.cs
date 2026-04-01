namespace Enigma.Cryptography.X509;

/// <summary>
/// Factory for creating X.509 certificate service instances.
/// </summary>
public interface IX509CertificateServiceFactory
{
    /// <summary>
    /// Creates an X.509 certificate service configured with the specified signature algorithm.
    /// </summary>
    /// <param name="signatureAlgorithm">
    /// The signature algorithm for certificate and CSR generation.
    /// Default is "SHA256WithRSA".
    /// </param>
    /// <returns>An <see cref="IX509CertificateService"/> instance.</returns>
    IX509CertificateService CreateService(string signatureAlgorithm = "SHA256WithRSA");
}
