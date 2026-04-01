using System;
using System.IO;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Enigma.Cryptography.X509;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace UnitTests.X509;

public class CertificateFormatTests
{
    private readonly IX509CertificateService _service = new X509CertificateServiceFactory().CreateService();
    private readonly IPublicKeyService _rsaService = new PublicKeyServiceFactory().CreateRsaService();

    [Fact]
    public void SaveCertDer_LoadCertDer_RoundTrip()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=DER Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var derBytes = X509Utils.SaveCertificate(cert);
        var loaded = X509Utils.LoadCertificate(derBytes);

        Assert.Equal(cert, loaded);
    }

    [Fact]
    public void SaveCertPem_LoadCertPem_RoundTrip()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=PEM Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        using var ms = new MemoryStream();
        X509Utils.SaveCertificateToPem(cert, ms);

        ms.Position = 0;
        var loaded = X509Utils.LoadCertificateFromPem(ms);

        Assert.Equal(cert, loaded);
    }

    [Fact]
    public void PemAndDer_ProduceSameCertificate()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Format Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        // Save/load via DER
        var derBytes = X509Utils.SaveCertificate(cert);
        var fromDer = X509Utils.LoadCertificate(derBytes);

        // Save/load via PEM
        using var ms = new MemoryStream();
        X509Utils.SaveCertificateToPem(cert, ms);
        ms.Position = 0;
        var fromPem = X509Utils.LoadCertificateFromPem(ms);

        Assert.Equal(fromDer, fromPem);
    }

    [Fact]
    public void SaveCertificateToPem_DoesNotDisposeStream()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Stream Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        using var ms = new MemoryStream();
        X509Utils.SaveCertificateToPem(cert, ms);

        // Stream should still be usable
        Assert.True(ms.CanRead);
        Assert.True(ms.CanWrite);
    }

    [Fact]
    public void LoadCertificateFromPem_DoesNotDisposeStream()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Stream Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        using var ms = new MemoryStream();
        X509Utils.SaveCertificateToPem(cert, ms);
        ms.Position = 0;

        X509Utils.LoadCertificateFromPem(ms);

        // Stream should still be usable
        Assert.True(ms.CanRead);
        Assert.True(ms.CanWrite);
    }

    [Fact]
    public void LoadCertificate_InvalidData_Throws()
    {
        var invalidData = new byte[] { 0x00, 0x01, 0x02, 0x03 };

        Assert.ThrowsAny<Exception>(() => X509Utils.LoadCertificate(invalidData));
    }

    [Fact]
    public void LoadCertificateFromPem_InvalidData_Throws()
    {
        using var ms = new MemoryStream("not a certificate"u8.ToArray());

        Assert.ThrowsAny<Exception>(() => X509Utils.LoadCertificateFromPem(ms));
    }
}
