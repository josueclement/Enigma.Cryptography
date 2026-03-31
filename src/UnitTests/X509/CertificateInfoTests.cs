using System;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Enigma.Cryptography.X509;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace UnitTests.X509;

public class CertificateInfoTests
{
    private readonly IX509CertificateService _service = new X509CertificateServiceFactory().CreateService();
    private readonly IPublicKeyService _rsaService = new PublicKeyServiceFactory().CreateRsaService();

    [Fact]
    public void GetCertificateInfo_Subject()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=info.example.com,O=InfoOrg,C=US"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Contains("CN=info.example.com", info.Subject);
        Assert.Contains("O=InfoOrg", info.Subject);
    }

    [Fact]
    public void GetCertificateInfo_SelfSigned_IssuerEqualsSubject()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=SelfSigned"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Equal(info.Subject, info.Issuer);
    }

    [Fact]
    public void GetCertificateInfo_Issued_IssuerDiffersFromSubject()
    {
        var caKeyPair = _rsaService.GenerateKeyPair(2048);
        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=Leaf"));
        var cert = _service.IssueCertificate(
            csr, caKeyPair, new X509Name("CN=CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Contains("CN=CA", info.Issuer);
        Assert.Contains("CN=Leaf", info.Subject);
        Assert.NotEqual(info.Subject, info.Issuer);
    }

    [Fact]
    public void GetCertificateInfo_SerialNumber()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.NotNull(info.SerialNumber);
        Assert.True(info.SerialNumber.SignValue > 0);
    }

    [Fact]
    public void GetCertificateInfo_ValidityDates()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var notBefore = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var notAfter = new DateTime(2035, 12, 31, 23, 59, 59, DateTimeKind.Utc);

        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            notBefore, notAfter);

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Equal(notBefore.Date, info.NotBefore.ToUniversalTime().Date);
        Assert.Equal(notAfter.Date, info.NotAfter.ToUniversalTime().Date);
    }

    [Fact]
    public void GetCertificateInfo_SignatureAlgorithm()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Contains("RSA", info.SignatureAlgorithm, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetCertificateInfo_Version3()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            basicConstraintsCa: true);

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Equal(3, info.Version);
    }

    [Fact]
    public void GetCertificateInfo_KeyUsage()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            keyUsage: KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment);

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.NotNull(info.KeyUsage);
        Assert.True(info.KeyUsage[0]); // DigitalSignature
        Assert.True(info.KeyUsage[2]); // KeyEncipherment
    }

    [Fact]
    public void GetCertificateInfo_NoKeyUsage_ReturnsNull()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Null(info.KeyUsage);
    }

    [Fact]
    public void GetCertificateInfo_SubjectAlternativeNames()
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

        Assert.Equal(2, info.SubjectAlternativeNames.Count);
        Assert.Contains("example.com", info.SubjectAlternativeNames);
        Assert.Contains("www.example.com", info.SubjectAlternativeNames);
    }

    [Fact]
    public void GetCertificateInfo_NoSans_ReturnsEmpty()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.Empty(info.SubjectAlternativeNames);
    }

    [Fact]
    public void GetCertificateInfo_IsCa_True()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            basicConstraintsCa: true);

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.True(info.IsCa);
    }

    [Fact]
    public void GetCertificateInfo_IsCa_False()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Leaf"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            basicConstraintsCa: false);

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.False(info.IsCa);
    }

    [Fact]
    public void GetCertificateInfo_IsValidNow()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Valid"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.True(info.IsValidNow);
    }

    [Fact]
    public void GetCertificateInfo_Expired_IsNotValidNow()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Expired"),
            DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddYears(-1));

        var info = X509Utils.GetCertificateInfo(cert);

        Assert.False(info.IsValidNow);
    }
}
