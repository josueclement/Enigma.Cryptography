using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Enigma.Cryptography.X509;

/// <summary>
/// Provides X.509 certificate operations using BouncyCastle.
/// </summary>
public class X509CertificateService : IX509CertificateService
{
    private readonly string _signatureAlgorithm;
    private readonly SecureRandom _random = new();

    internal X509CertificateService(string signatureAlgorithm)
    {
        _signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
    }

    /// <inheritdoc />
    public X509Certificate GenerateSelfSignedCertificate(
        AsymmetricCipherKeyPair keyPair,
        X509Name subject,
        DateTime notBefore,
        DateTime notAfter,
        int? keyUsage = null,
        bool? basicConstraintsCa = null,
        GeneralNames? subjectAlternativeNames = null)
    {
        if (keyPair is null) throw new ArgumentNullException(nameof(keyPair));
        if (subject is null) throw new ArgumentNullException(nameof(subject));

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(GenerateSerialNumber());
        generator.SetIssuerDN(subject);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(keyPair.Public);

        AddExtensions(generator, keyUsage, basicConstraintsCa, subjectAlternativeNames);

        var signatureFactory = new Asn1SignatureFactory(_signatureAlgorithm, keyPair.Private, _random);
        return generator.Generate(signatureFactory);
    }

    /// <inheritdoc />
    public Pkcs10CertificationRequest GenerateCsr(
        AsymmetricCipherKeyPair keyPair,
        X509Name subject)
    {
        if (keyPair is null) throw new ArgumentNullException(nameof(keyPair));
        if (subject is null) throw new ArgumentNullException(nameof(subject));

        return new Pkcs10CertificationRequest(
            _signatureAlgorithm,
            subject,
            keyPair.Public,
            null,
            keyPair.Private);
    }

    /// <inheritdoc />
    public bool VerifyCsr(Pkcs10CertificationRequest csr)
    {
        if (csr is null) throw new ArgumentNullException(nameof(csr));

        return csr.Verify();
    }

    /// <inheritdoc />
    public X509Certificate IssueCertificate(
        Pkcs10CertificationRequest csr,
        AsymmetricCipherKeyPair issuerKeyPair,
        X509Name issuerName,
        DateTime notBefore,
        DateTime notAfter,
        int? keyUsage = null,
        bool? basicConstraintsCa = null,
        GeneralNames? subjectAlternativeNames = null)
    {
        if (csr is null) throw new ArgumentNullException(nameof(csr));
        if (issuerKeyPair is null) throw new ArgumentNullException(nameof(issuerKeyPair));
        if (issuerName is null) throw new ArgumentNullException(nameof(issuerName));

        var csrInfo = csr.GetCertificationRequestInfo();

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(GenerateSerialNumber());
        generator.SetIssuerDN(issuerName);
        generator.SetSubjectDN(csrInfo.Subject);
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(csr.GetPublicKey());

        AddExtensions(generator, keyUsage, basicConstraintsCa, subjectAlternativeNames);

        var signatureFactory = new Asn1SignatureFactory(_signatureAlgorithm, issuerKeyPair.Private, _random);
        return generator.Generate(signatureFactory);
    }

    /// <inheritdoc />
    public bool ValidateChain(
        X509Certificate certificate,
        IEnumerable<X509Certificate> trustedCaCertificates)
    {
        if (certificate is null) throw new ArgumentNullException(nameof(certificate));
        if (trustedCaCertificates is null) throw new ArgumentNullException(nameof(trustedCaCertificates));

        try
        {
            var trustAnchors = new HashSet<TrustAnchor>();
            var intermediateCerts = new List<X509Certificate>();

            foreach (var caCert in trustedCaCertificates)
            {
                var basicConstraints = caCert.GetBasicConstraints();
                if (basicConstraints >= 0 && caCert.IssuerDN.Equivalent(caCert.SubjectDN))
                {
                    // Self-signed CA — use as trust anchor
                    trustAnchors.Add(new TrustAnchor(caCert, null));
                }
                else
                {
                    // Intermediate CA
                    intermediateCerts.Add(caCert);
                }
            }

            if (trustAnchors.Count == 0)
                return false;

            // Build the cert path: end-entity + intermediates
            var certList = new List<X509Certificate> { certificate };
            certList.AddRange(intermediateCerts);

            var certStoreBuilder = CollectionUtilities.CreateStore(certList);
            var certPath = new PkixCertPath(certList);

            var parameters = new PkixParameters(trustAnchors)
            {
                IsRevocationEnabled = false
            };
            parameters.AddStoreCert(certStoreBuilder);

            var validator = new PkixCertPathValidator();
            validator.Validate(certPath, parameters);

            return true;
        }
        catch (PkixCertPathValidatorException)
        {
            return false;
        }
    }

    private BigInteger GenerateSerialNumber()
    {
        return BigIntegers.CreateRandomBigInteger(128, _random);
    }

    private static void AddExtensions(
        X509V3CertificateGenerator generator,
        int? keyUsage,
        bool? basicConstraintsCa,
        GeneralNames? subjectAlternativeNames)
    {
        if (keyUsage.HasValue)
        {
            generator.AddExtension(
                X509Extensions.KeyUsage,
                critical: true,
                new KeyUsage(keyUsage.Value));
        }

        if (basicConstraintsCa.HasValue)
        {
            generator.AddExtension(
                X509Extensions.BasicConstraints,
                critical: true,
                new BasicConstraints(basicConstraintsCa.Value));
        }

        if (subjectAlternativeNames is not null)
        {
            generator.AddExtension(
                X509Extensions.SubjectAlternativeName,
                critical: false,
                subjectAlternativeNames);
        }
    }
}
