using System;
using System.Collections.Generic;
using Org.BouncyCastle.Math;

namespace Enigma.Cryptography.X509;

/// <summary>
/// Read-only information extracted from an X.509 certificate.
/// </summary>
public sealed class CertificateInfo
{
    /// <summary>
    /// The subject distinguished name of the certificate.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// The issuer distinguished name of the certificate.
    /// </summary>
    public string Issuer { get; }

    /// <summary>
    /// The serial number of the certificate.
    /// </summary>
    public BigInteger SerialNumber { get; }

    /// <summary>
    /// The start of the certificate validity period.
    /// </summary>
    public DateTime NotBefore { get; }

    /// <summary>
    /// The end of the certificate validity period.
    /// </summary>
    public DateTime NotAfter { get; }

    /// <summary>
    /// The signature algorithm used to sign the certificate.
    /// </summary>
    public string SignatureAlgorithm { get; }

    /// <summary>
    /// The X.509 version of the certificate.
    /// </summary>
    public int Version { get; }

    /// <summary>
    /// The key usage flags from the KeyUsage extension, or null if the extension is not present.
    /// </summary>
    public bool[]? KeyUsage { get; }

    /// <summary>
    /// The subject alternative names from the SubjectAlternativeName extension.
    /// Empty if the extension is not present.
    /// </summary>
    public IReadOnlyList<string> SubjectAlternativeNames { get; }

    /// <summary>
    /// Whether the certificate is a CA certificate (from BasicConstraints extension).
    /// </summary>
    public bool IsCa { get; }

    /// <summary>
    /// Whether the certificate is currently within its validity period.
    /// </summary>
    public bool IsValidNow { get; }

    internal CertificateInfo(
        string subject,
        string issuer,
        BigInteger serialNumber,
        DateTime notBefore,
        DateTime notAfter,
        string signatureAlgorithm,
        int version,
        bool[]? keyUsage,
        IReadOnlyList<string> subjectAlternativeNames,
        bool isCa,
        bool isValidNow)
    {
        Subject = subject;
        Issuer = issuer;
        SerialNumber = serialNumber;
        NotBefore = notBefore;
        NotAfter = notAfter;
        SignatureAlgorithm = signatureAlgorithm;
        Version = version;
        KeyUsage = keyUsage;
        SubjectAlternativeNames = subjectAlternativeNames;
        IsCa = isCa;
        IsValidNow = isValidNow;
    }
}
