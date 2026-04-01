using System;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Enigma.Cryptography.X509;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace UnitTests.X509;

public class IssueCertificateTests
{
    private readonly IX509CertificateService _service = new X509CertificateServiceFactory().CreateService();
    private readonly IPublicKeyService _rsaService = new PublicKeyServiceFactory().CreateRsaService();

    [Fact]
    public void IssueCertificate_HasCorrectIssuer()
    {
        var caKeyPair = _rsaService.GenerateKeyPair(2048);
        var caName = new X509Name("CN=Test CA");

        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=leaf.example.com"));

        var cert = _service.IssueCertificate(
            csr, caKeyPair, caName,
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        Assert.Contains("CN=Test CA", cert.IssuerDN.ToString());
        Assert.Contains("CN=leaf.example.com", cert.SubjectDN.ToString());
    }

    [Fact]
    public void IssueCertificate_SubjectFromCsr()
    {
        var caKeyPair = _rsaService.GenerateKeyPair(2048);
        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=from-csr.example.com,O=CSR Org"));

        var cert = _service.IssueCertificate(
            csr, caKeyPair, new X509Name("CN=CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        Assert.Contains("CN=from-csr.example.com", cert.SubjectDN.ToString());
        Assert.Contains("O=CSR Org", cert.SubjectDN.ToString());
    }

    [Fact]
    public void IssueCertificate_SignedByIssuer()
    {
        var caKeyPair = _rsaService.GenerateKeyPair(2048);
        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=Leaf"));

        var cert = _service.IssueCertificate(
            csr, caKeyPair, new X509Name("CN=CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        // Should be verifiable with the CA's public key
        cert.Verify(caKeyPair.Public);
    }

    [Fact]
    public void IssueCertificate_WithExtensions()
    {
        var caKeyPair = _rsaService.GenerateKeyPair(2048);
        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=Leaf"));

        var sans = new GeneralNames(new GeneralName(GeneralName.DnsName, "leaf.example.com"));

        var cert = _service.IssueCertificate(
            csr, caKeyPair, new X509Name("CN=CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            keyUsage: KeyUsage.DigitalSignature,
            basicConstraintsCa: false,
            subjectAlternativeNames: sans);

        var info = X509Utils.GetCertificateInfo(cert);
        Assert.False(info.IsCa);
        Assert.Contains("leaf.example.com", info.SubjectAlternativeNames);
    }

    [Fact]
    public void IssueCertificate_BuildThreeLevelChain()
    {
        // Root CA
        var rootKeyPair = _rsaService.GenerateKeyPair(2048);
        var rootName = new X509Name("CN=Root CA");
        var rootCert = _service.GenerateSelfSignedCertificate(
            rootKeyPair, rootName,
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(10),
            keyUsage: KeyUsage.KeyCertSign | KeyUsage.CrlSign,
            basicConstraintsCa: true);

        // Intermediate CA
        var intermediateKeyPair = _rsaService.GenerateKeyPair(2048);
        var intermediateCsr = _service.GenerateCsr(intermediateKeyPair, new X509Name("CN=Intermediate CA"));
        var intermediateCert = _service.IssueCertificate(
            intermediateCsr, rootKeyPair, rootName,
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(5),
            keyUsage: KeyUsage.KeyCertSign | KeyUsage.CrlSign,
            basicConstraintsCa: true);

        // Leaf
        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var leafCsr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=leaf.example.com"));
        var leafCert = _service.IssueCertificate(
            leafCsr, intermediateKeyPair, new X509Name("CN=Intermediate CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            keyUsage: KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment,
            basicConstraintsCa: false);

        // Verify chain signatures
        rootCert.Verify(rootKeyPair.Public);
        intermediateCert.Verify(rootKeyPair.Public);
        leafCert.Verify(intermediateKeyPair.Public);
    }
}
