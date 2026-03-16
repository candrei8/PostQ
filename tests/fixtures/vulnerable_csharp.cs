/**
 * Fixture: C# code with quantum-vulnerable cryptography.
 * Every usage here should trigger at least one finding.
 */

using System;
using System.Security.Cryptography;

public class VulnerableCrypto
{
    // RSA — quantum vulnerable
    public void GenerateRSAKey()
    {
        using var rsa = RSA.Create(2048);
        var rsaProvider = new RSACryptoServiceProvider(1024);
    }

    // DSA — quantum vulnerable
    public void GenerateDSAKey()
    {
        using var dsa = DSA.Create();
        var dsaProvider = new DSACryptoServiceProvider();
    }

    // MD5 — broken hash
    public byte[] HashMD5(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    // SHA-1 — broken hash
    public byte[] HashSHA1(byte[] data)
    {
        using var sha1 = SHA1.Create();
        return sha1.ComputeHash(data);
    }

    // DES — broken cipher
    public void EncryptDES()
    {
        using var des = DESCryptoServiceProvider();
        using var tripleDes = TripleDESCryptoServiceProvider();
    }

    // AES in ECB mode
    public void EncryptAESECB()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
    }

    // Weak random for crypto
    public int WeakRandom()
    {
        var random = new Random();
        return random.Next();
    }
}
