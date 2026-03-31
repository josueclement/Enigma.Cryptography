using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.X509;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace UnitTests.X509;

public class CsrTests
{
    private readonly IX509CertificateService _service = new X509CertificateServiceFactory().CreateService();
    private readonly IPublicKeyService _rsaService = new PublicKeyServiceFactory().CreateRsaService();

    [Fact]
    public void GenerateCsr_ReturnsNonNull()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var subject = new X509Name("CN=test.example.com,O=TestOrg");

        var csr = _service.GenerateCsr(keyPair, subject);

        Assert.NotNull(csr);
    }

    [Fact]
    public void GenerateCsr_HasCorrectSubject()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var subject = new X509Name("CN=test.example.com,O=TestOrg");

        var csr = _service.GenerateCsr(keyPair, subject);
        var csrInfo = csr.GetCertificationRequestInfo();

        Assert.Contains("CN=test.example.com", csrInfo.Subject.ToString());
        Assert.Contains("O=TestOrg", csrInfo.Subject.ToString());
    }

    [Fact]
    public void GenerateCsr_SignatureIsValid()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);

        var csr = _service.GenerateCsr(keyPair, new X509Name("CN=Test"));

        Assert.True(_service.VerifyCsr(csr));
    }

    [Fact]
    public void GenerateCsr_ContainsPublicKey()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);

        var csr = _service.GenerateCsr(keyPair, new X509Name("CN=Test"));
        var csrPublicKey = csr.GetPublicKey();

        Assert.Equal(keyPair.Public, csrPublicKey);
    }

    [Fact]
    public void GenerateCsr_PemRoundTrip()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(keyPair, new X509Name("CN=Test"));

        // Encode and decode the CSR via DER bytes
        var encoded = csr.GetEncoded();
        var reloaded = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(encoded);

        Assert.True(_service.VerifyCsr(reloaded));
        Assert.Equal(
            csr.GetCertificationRequestInfo().Subject.ToString(),
            reloaded.GetCertificationRequestInfo().Subject.ToString());
    }
}
