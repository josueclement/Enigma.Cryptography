using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace Enigma.Cryptography.X509;

/// <summary>
/// Provides X.509 certificate operations including generation, signing, and chain validation.
/// </summary>
/// <remarks>
/// For loading, saving, and inspecting certificates, use <see cref="Utils.X509Utils"/>.
/// </remarks>
public interface IX509CertificateService
{
    // === Certificate Generation ===

    /// <summary>
    /// Generates a self-signed X.509 v3 certificate.
    /// </summary>
    /// <param name="keyPair">The key pair to embed in the certificate (public key) and sign with (private key).</param>
    /// <param name="subject">The subject distinguished name.</param>
    /// <param name="notBefore">The start of the certificate validity period.</param>
    /// <param name="notAfter">The end of the certificate validity period.</param>
    /// <param name="keyUsage">
    /// Optional key usage flags (use <see cref="KeyUsage"/> constants, e.g.,
    /// <c>KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment</c>). Null to omit.
    /// </param>
    /// <param name="basicConstraintsCa">
    /// If true, marks as a CA certificate. If false, marks as end-entity.
    /// If null, the BasicConstraints extension is omitted.
    /// </param>
    /// <param name="subjectAlternativeNames">Optional subject alternative names. Null to omit.</param>
    /// <returns>The generated self-signed certificate.</returns>
    X509Certificate GenerateSelfSignedCertificate(
        AsymmetricCipherKeyPair keyPair,
        X509Name subject,
        DateTime notBefore,
        DateTime notAfter,
        int? keyUsage = null,
        bool? basicConstraintsCa = null,
        GeneralNames? subjectAlternativeNames = null);

    // === CSR (PKCS#10) ===

    /// <summary>
    /// Creates a PKCS#10 certificate signing request.
    /// </summary>
    /// <param name="keyPair">The key pair (private key signs the CSR, public key is embedded).</param>
    /// <param name="subject">The subject distinguished name for the CSR.</param>
    /// <returns>The PKCS#10 certification request.</returns>
    Pkcs10CertificationRequest GenerateCsr(
        AsymmetricCipherKeyPair keyPair,
        X509Name subject);

    /// <summary>
    /// Verifies that a CSR's signature is valid.
    /// </summary>
    /// <param name="csr">The PKCS#10 CSR to verify.</param>
    /// <returns>True if the CSR signature is valid; otherwise false.</returns>
    bool VerifyCsr(Pkcs10CertificationRequest csr);

    // === Issue Certificate ===

    /// <summary>
    /// Issues a certificate by signing a CSR with a CA key pair.
    /// </summary>
    /// <param name="csr">The certificate signing request to fulfill.</param>
    /// <param name="issuerKeyPair">The CA's key pair used to sign the certificate.</param>
    /// <param name="issuerName">The issuer distinguished name.</param>
    /// <param name="notBefore">The start of the certificate validity period.</param>
    /// <param name="notAfter">The end of the certificate validity period.</param>
    /// <param name="keyUsage">Optional key usage flags. Null to omit.</param>
    /// <param name="basicConstraintsCa">
    /// If true, marks as a CA certificate. If false, marks as end-entity.
    /// If null, the BasicConstraints extension is omitted.
    /// </param>
    /// <param name="subjectAlternativeNames">Optional subject alternative names. Null to omit.</param>
    /// <returns>The issued certificate.</returns>
    X509Certificate IssueCertificate(
        Pkcs10CertificationRequest csr,
        AsymmetricCipherKeyPair issuerKeyPair,
        X509Name issuerName,
        DateTime notBefore,
        DateTime notAfter,
        int? keyUsage = null,
        bool? basicConstraintsCa = null,
        GeneralNames? subjectAlternativeNames = null);

    // === Chain Validation ===

    /// <summary>
    /// Validates a certificate chain against a set of trusted CA certificates.
    /// </summary>
    /// <param name="certificate">The end-entity certificate to validate.</param>
    /// <param name="trustedCaCertificates">The set of trusted CA certificates (roots and intermediates).</param>
    /// <returns>True if the certificate chain is valid; otherwise false.</returns>
    bool ValidateChain(
        X509Certificate certificate,
        IEnumerable<X509Certificate> trustedCaCertificates);
}
