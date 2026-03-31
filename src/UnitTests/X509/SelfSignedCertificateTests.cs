using System;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Enigma.Cryptography.X509;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace UnitTests.X509;

public class SelfSignedCertificateTests
{
    private readonly IX509CertificateService _service = new X509CertificateServiceFactory().CreateService();
    private readonly IPublicKeyService _rsaService = new PublicKeyServiceFactory().CreateRsaService();

    [Fact]
    public void GenerateSelfSigned_ReturnsNonNullCertificate()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var subject = new X509Name("CN=Test");

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, subject,
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        Assert.NotNull(cert);
    }

    [Fact]
    public void GenerateSelfSigned_HasCorrectSubject()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var subject = new X509Name("CN=test.example.com,O=TestOrg,C=US");

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, subject,
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        Assert.Contains("CN=test.example.com", cert.SubjectDN.ToString());
        Assert.Contains("O=TestOrg", cert.SubjectDN.ToString());
    }

    [Fact]
    public void GenerateSelfSigned_IssuerEqualsSubject()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var subject = new X509Name("CN=SelfSigned");

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, subject,
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        Assert.Equal(cert.SubjectDN, cert.IssuerDN);
    }

    [Fact]
    public void GenerateSelfSigned_ValidityPeriodIsCorrect()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var notBefore = new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc);
        var notAfter = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc);

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            notBefore, notAfter);

        Assert.Equal(notBefore.Date, cert.NotBefore.ToUniversalTime().Date);
        Assert.Equal(notAfter.Date, cert.NotAfter.ToUniversalTime().Date);
    }

    [Fact]
    public void GenerateSelfSigned_HasSerialNumber()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        Assert.True(cert.SerialNumber.SignValue > 0);
    }

    [Fact]
    public void GenerateSelfSigned_WithKeyUsageExtension()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            keyUsage: KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment);

        var ku = cert.GetKeyUsage();
        Assert.NotNull(ku);
        Assert.True(ku[0]); // DigitalSignature
        Assert.True(ku[2]); // KeyEncipherment
    }

    [Fact]
    public void GenerateSelfSigned_WithBasicConstraintsCA()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            basicConstraintsCa: true);

        Assert.True(cert.GetBasicConstraints() >= 0);
    }

    [Fact]
    public void GenerateSelfSigned_WithBasicConstraintsEndEntity()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            basicConstraintsCa: false);

        Assert.Equal(-1, cert.GetBasicConstraints());
    }

    [Fact]
    public void GenerateSelfSigned_WithSubjectAltNames()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var sans = new GeneralNames(new[]
        {
            new GeneralName(GeneralName.DnsName, "example.com"),
            new GeneralName(GeneralName.DnsName, "www.example.com")
        });

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=example.com"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            subjectAlternativeNames: sans);

        var info = X509Utils.GetCertificateInfo(cert);
        Assert.Contains("example.com", info.SubjectAlternativeNames);
        Assert.Contains("www.example.com", info.SubjectAlternativeNames);
    }

    [Fact]
    public void GenerateSelfSigned_SignatureIsValid()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        // Self-signed: verify with its own public key
        cert.Verify(keyPair.Public);
    }
}
