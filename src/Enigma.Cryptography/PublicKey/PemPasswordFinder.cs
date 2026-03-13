using System;
using Org.BouncyCastle.OpenSsl;

namespace Enigma.Cryptography.PublicKey;

/// <summary>
/// PEM password finder implementation
/// </summary>
public class PemPasswordFinder : IPasswordFinder, IDisposable
{
    private readonly char[] _password;
    private bool _disposed;

    /// <summary>
    /// Creates a new PemPasswordFinder with the given password
    /// </summary>
    /// <param name="password">Password</param>
    public PemPasswordFinder(string password)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        _password = password.ToCharArray();
    }

    /// <inheritdoc />
    public char[] GetPassword()
    {
        var copy = new char[_password.Length];
        Array.Copy(_password, copy, _password.Length);
        return copy;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            Array.Clear(_password, 0, _password.Length);
            _disposed = true;
        }
    }
}
