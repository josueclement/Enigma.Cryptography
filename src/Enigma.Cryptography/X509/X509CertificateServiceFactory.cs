namespace Enigma.Cryptography.X509;

/// <summary>
/// Factory class for creating X.509 certificate service instances.
/// </summary>
public class X509CertificateServiceFactory : IX509CertificateServiceFactory
{
    /// <inheritdoc />
    public IX509CertificateService CreateService(string signatureAlgorithm = "SHA256WithRSA")
        => new X509CertificateService(signatureAlgorithm);
}
