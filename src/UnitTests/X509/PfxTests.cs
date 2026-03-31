using System;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.Utils;
using Enigma.Cryptography.X509;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace UnitTests.X509;

public class PfxTests
{
    private readonly IX509CertificateService _service = new X509CertificateServiceFactory().CreateService();
    private readonly IPublicKeyService _rsaService = new PublicKeyServiceFactory().CreateRsaService();

    [Fact]
    public void ExportLoadPfx_RoundTrip()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=PFX Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var pfxData = X509Utils.ExportToPfx("test", cert, keyPair.Private, "password123");
        var (loadedCert, loadedKey) = X509Utils.LoadFromPfx(pfxData, "password123");

        Assert.Equal(cert, loadedCert);
        Assert.NotNull(loadedKey);
    }

    [Fact]
    public void LoadFromPfx_ExtractedKeyCanSign()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=PFX Sign Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var pfxData = X509Utils.ExportToPfx("test", cert, keyPair.Private, "password123");
        var (loadedCert, loadedKey) = X509Utils.LoadFromPfx(pfxData, "password123");

        // Use the extracted private key to sign, verify with cert's public key
        var data = "test data"u8.ToArray();
        var signature = _rsaService.Sign(data, loadedKey);
        var publicKey = loadedCert.GetPublicKey();
        Assert.True(_rsaService.Verify(data, signature, publicKey));
    }

    [Fact]
    public void ExportPfx_WithChain()
    {
        var rootKeyPair = _rsaService.GenerateKeyPair(2048);
        var rootCert = _service.GenerateSelfSignedCertificate(
            rootKeyPair, new X509Name("CN=Root CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(10),
            basicConstraintsCa: true);

        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=Leaf"));
        var leafCert = _service.IssueCertificate(
            csr, rootKeyPair, new X509Name("CN=Root CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var pfxData = X509Utils.ExportToPfx("leaf", leafCert, leafKeyPair.Private, "pass",
            chain: new[] { rootCert });

        var (loadedCert, loadedKey) = X509Utils.LoadFromPfx(pfxData, "pass");
        Assert.Equal(leafCert, loadedCert);
        Assert.NotNull(loadedKey);
    }

    [Fact]
    public void LoadFromPfx_WrongPassword_Throws()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=PFX Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var pfxData = X509Utils.ExportToPfx("test", cert, keyPair.Private, "correct-password");

        Assert.ThrowsAny<Exception>(() => X509Utils.LoadFromPfx(pfxData, "wrong-password"));
    }

    [Fact]
    public void ExportPfx_EmptyPassword_RoundTrips()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Empty Password"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var pfxData = X509Utils.ExportToPfx("test", cert, keyPair.Private, "");
        var (loadedCert, _) = X509Utils.LoadFromPfx(pfxData, "");

        Assert.Equal(cert, loadedCert);
    }
}
