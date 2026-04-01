using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Enigma.Cryptography.X509;

namespace Enigma.Cryptography.Utils;

/// <summary>
/// X.509 certificate utilities for loading, saving, and inspecting certificates.
/// </summary>
public static class X509Utils
{
    /// <summary>
    /// Loads an X.509 certificate from DER-encoded bytes.
    /// </summary>
    /// <param name="data">The DER-encoded certificate bytes.</param>
    /// <returns>The parsed certificate.</returns>
    public static X509Certificate LoadCertificate(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        var parser = new X509CertificateParser();
        return parser.ReadCertificate(data)
               ?? throw new InvalidOperationException("No certificate found in the provided data.");
    }

    /// <summary>
    /// Loads an X.509 certificate from a PEM-encoded stream.
    /// </summary>
    /// <param name="input">The stream containing PEM-encoded certificate data.</param>
    /// <returns>The parsed certificate.</returns>
    public static X509Certificate LoadCertificateFromPem(Stream input)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        using var reader = new StreamReader(input, Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
            bufferSize: 1024, leaveOpen: true);
        var pemReader = new PemReader(reader);
        var obj = pemReader.ReadObject();

        return obj switch
        {
            X509Certificate cert => cert,
            _ => throw new InvalidOperationException("No X.509 certificate found in PEM data.")
        };
    }

    /// <summary>
    /// Gets the DER-encoded representation of a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to encode.</param>
    /// <returns>The DER-encoded certificate bytes.</returns>
    public static byte[] SaveCertificate(X509Certificate certificate)
    {
        if (certificate is null) throw new ArgumentNullException(nameof(certificate));

        return certificate.GetEncoded();
    }

    /// <summary>
    /// Saves a certificate to a stream in PEM format.
    /// </summary>
    /// <param name="certificate">The certificate to save.</param>
    /// <param name="output">The output stream.</param>
    public static void SaveCertificateToPem(X509Certificate certificate, Stream output)
    {
        if (certificate is null) throw new ArgumentNullException(nameof(certificate));
        if (output is null) throw new ArgumentNullException(nameof(output));

        using var writer = new StreamWriter(output, Encoding.UTF8, bufferSize: 1024, leaveOpen: true);
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(certificate);
    }

    /// <summary>
    /// Exports a certificate and its private key to a PKCS#12 (PFX) byte array.
    /// </summary>
    /// <param name="alias">The friendly name for the entry in the PFX store.</param>
    /// <param name="certificate">The certificate to export.</param>
    /// <param name="privateKey">The private key corresponding to the certificate.</param>
    /// <param name="password">The password to protect the PFX.</param>
    /// <param name="chain">Optional additional certificates to include in the chain.</param>
    /// <returns>The PKCS#12 encoded data.</returns>
    public static byte[] ExportToPfx(
        string alias,
        X509Certificate certificate,
        AsymmetricKeyParameter privateKey,
        string password,
        X509Certificate[]? chain = null)
    {
        if (alias is null) throw new ArgumentNullException(nameof(alias));
        if (certificate is null) throw new ArgumentNullException(nameof(certificate));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));
        if (password is null) throw new ArgumentNullException(nameof(password));

        var store = new Pkcs12StoreBuilder().Build();

        var certChain = new List<X509CertificateEntry> { new(certificate) };
        if (chain is not null)
        {
            foreach (var chainCert in chain)
                certChain.Add(new X509CertificateEntry(chainCert));
        }

        store.SetKeyEntry(alias, new AsymmetricKeyEntry(privateKey), certChain.ToArray());

        var passwordChars = password.ToCharArray();
        try
        {
            using var ms = new MemoryStream();
            store.Save(ms, passwordChars, new SecureRandom());
            return ms.ToArray();
        }
        finally
        {
            Array.Clear(passwordChars, 0, passwordChars.Length);
        }
    }

    /// <summary>
    /// Loads a certificate and private key from PKCS#12 (PFX) data.
    /// </summary>
    /// <param name="data">The PKCS#12 encoded data.</param>
    /// <param name="password">The password to unlock the PFX.</param>
    /// <returns>A tuple containing the certificate and its associated private key.</returns>
    public static (X509Certificate certificate, AsymmetricKeyParameter privateKey) LoadFromPfx(
        byte[] data,
        string password)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (password is null) throw new ArgumentNullException(nameof(password));

        var store = new Pkcs12StoreBuilder().Build();

        var passwordChars = password.ToCharArray();
        try
        {
            using var ms = new MemoryStream(data);
            store.Load(ms, passwordChars);
        }
        finally
        {
            Array.Clear(passwordChars, 0, passwordChars.Length);
        }

        foreach (var storeAlias in store.Aliases)
        {
            if (store.IsKeyEntry(storeAlias))
            {
                var keyEntry = store.GetKey(storeAlias);
                var certChain = store.GetCertificateChain(storeAlias);

                if (certChain is { Length: > 0 })
                {
                    return (certChain[0].Certificate, keyEntry.Key);
                }
            }
        }

        throw new InvalidOperationException("No key entry with a certificate found in the PKCS#12 data.");
    }

    /// <summary>
    /// Extracts readable information from a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>A <see cref="CertificateInfo"/> containing the certificate's properties.</returns>
    public static CertificateInfo GetCertificateInfo(X509Certificate certificate)
    {
        if (certificate is null) throw new ArgumentNullException(nameof(certificate));

        var sans = ExtractSubjectAlternativeNames(certificate);
        var isCa = ExtractIsCa(certificate);
        var isValidNow = IsCurrentlyValid(certificate);

        return new CertificateInfo(
            subject: certificate.SubjectDN.ToString(),
            issuer: certificate.IssuerDN.ToString(),
            serialNumber: certificate.SerialNumber,
            notBefore: certificate.NotBefore,
            notAfter: certificate.NotAfter,
            signatureAlgorithm: certificate.SigAlgName,
            version: certificate.Version,
            keyUsage: certificate.GetKeyUsage(),
            subjectAlternativeNames: sans,
            isCa: isCa,
            isValidNow: isValidNow);
    }

    private static IReadOnlyList<string> ExtractSubjectAlternativeNames(X509Certificate certificate)
    {
        var result = new List<string>();

        try
        {
            var sanExtension = certificate.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (sanExtension is null)
                return result;

            var asn1Object = X509ExtensionUtilities.FromExtensionValue(sanExtension);
            var generalNames = GeneralNames.GetInstance(asn1Object);

            foreach (var name in generalNames.GetNames())
            {
                result.Add(name.Name.ToString()!);
            }
        }
        catch
        {
            // If SAN parsing fails, return empty list
        }

        return result;
    }

    private static bool ExtractIsCa(X509Certificate certificate)
    {
        return certificate.GetBasicConstraints() >= 0;
    }

    private static bool IsCurrentlyValid(X509Certificate certificate)
    {
        try
        {
            certificate.CheckValidity(DateTime.UtcNow);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
