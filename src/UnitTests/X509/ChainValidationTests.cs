using System;
using Enigma.Cryptography.PublicKey;
using Enigma.Cryptography.X509;
using Org.BouncyCastle.Asn1.X509;
using Xunit;

namespace UnitTests.X509;

public class ChainValidationTests
{
    private readonly IX509CertificateService _service = new X509CertificateServiceFactory().CreateService();
    private readonly IPublicKeyService _rsaService = new PublicKeyServiceFactory().CreateRsaService();

    [Fact]
    public void ValidateChain_FullChain_Succeeds()
    {
        var (rootCert, rootKeyPair) = CreateRootCa();
        var (intermediateCert, intermediateKeyPair) = CreateIntermediateCa(rootKeyPair);
        var leafCert = CreateLeaf(intermediateKeyPair);

        var result = _service.ValidateChain(leafCert, new[] { intermediateCert, rootCert });

        Assert.True(result);
    }

    [Fact]
    public void ValidateChain_LeafAgainstRootOnly_Fails()
    {
        var (rootCert, rootKeyPair) = CreateRootCa();
        var (_, intermediateKeyPair) = CreateIntermediateCa(rootKeyPair);
        var leafCert = CreateLeaf(intermediateKeyPair);

        // Missing intermediate — should fail
        var result = _service.ValidateChain(leafCert, new[] { rootCert });

        Assert.False(result);
    }

    [Fact]
    public void ValidateChain_SelfSignedAgainstItself_Succeeds()
    {
        var (rootCert, _) = CreateRootCa();

        var result = _service.ValidateChain(rootCert, new[] { rootCert });

        Assert.True(result);
    }

    [Fact]
    public void ValidateChain_UntrustedRoot_Fails()
    {
        var (_, rootKeyPair) = CreateRootCa();
        var (_, intermediateKeyPair) = CreateIntermediateCa(rootKeyPair);
        var leafCert = CreateLeaf(intermediateKeyPair);

        // Create a different, unrelated root
        var (untrustedRoot, _) = CreateRootCa();

        var result = _service.ValidateChain(leafCert, new[] { untrustedRoot });

        Assert.False(result);
    }

    [Fact]
    public void ValidateChain_ExpiredLeaf_Fails()
    {
        var (rootCert, rootKeyPair) = CreateRootCa();
        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=Expired Leaf"));
        var expiredLeaf = _service.IssueCertificate(
            csr, rootKeyPair, new X509Name("CN=Root CA"),
            DateTime.UtcNow.AddYears(-3), DateTime.UtcNow.AddYears(-1));

        var result = _service.ValidateChain(expiredLeaf, new[] { rootCert });

        Assert.False(result);
    }

    [Fact]
    public void ValidateChain_NotYetValidLeaf_Fails()
    {
        var (rootCert, rootKeyPair) = CreateRootCa();
        var leafKeyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(leafKeyPair, new X509Name("CN=Future Leaf"));
        var futureLeaf = _service.IssueCertificate(
            csr, rootKeyPair, new X509Name("CN=Root CA"),
            DateTime.UtcNow.AddYears(1), DateTime.UtcNow.AddYears(2));

        var result = _service.ValidateChain(futureLeaf, new[] { rootCert });

        Assert.False(result);
    }

    [Fact]
    public void ValidateChain_EmptyTrustAnchors_Fails()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Test"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1));

        var result = _service.ValidateChain(cert, Array.Empty<Org.BouncyCastle.X509.X509Certificate>());

        Assert.False(result);
    }

    private (Org.BouncyCastle.X509.X509Certificate cert, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair) CreateRootCa()
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var cert = _service.GenerateSelfSignedCertificate(
            keyPair, new X509Name("CN=Root CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(10),
            keyUsage: KeyUsage.KeyCertSign | KeyUsage.CrlSign,
            basicConstraintsCa: true);
        return (cert, keyPair);
    }

    private (Org.BouncyCastle.X509.X509Certificate cert, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair) CreateIntermediateCa(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair rootKeyPair)
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(keyPair, new X509Name("CN=Intermediate CA"));
        var cert = _service.IssueCertificate(
            csr, rootKeyPair, new X509Name("CN=Root CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(5),
            keyUsage: KeyUsage.KeyCertSign | KeyUsage.CrlSign,
            basicConstraintsCa: true);
        return (cert, keyPair);
    }

    private Org.BouncyCastle.X509.X509Certificate CreateLeaf(
        Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair issuerKeyPair)
    {
        var keyPair = _rsaService.GenerateKeyPair(2048);
        var csr = _service.GenerateCsr(keyPair, new X509Name("CN=leaf.example.com"));
        return _service.IssueCertificate(
            csr, issuerKeyPair, new X509Name("CN=Intermediate CA"),
            DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddYears(1),
            keyUsage: KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment,
            basicConstraintsCa: false);
    }
}
