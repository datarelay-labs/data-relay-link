# FrpCrypto.ps1 — ECDSA P-256, canonical JSON, PBKDF2 token wrap, HMAC helpers.
# Prefer Add-Type C# helpers. No external NuGet. Compatible with Windows PowerShell 5.1 and PowerShell 7.

if ((Test-Path variable:script:FrpCryptoLoaded) -and $script:FrpCryptoLoaded) { return }
$script:FrpCryptoLoaded = $true

$script:FrpCryptoTypeReady = $false

function Initialize-FrpCryptoTypes {
    if ($script:FrpCryptoTypeReady) { return }
    if ([type]::GetType('FrpCryptoNative')) {
        $script:FrpCryptoTypeReady = $true
        return
    }

    $modern = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class FrpCryptoNative
{
    public const int Pbkdf2Iterations = 200000;
    public static readonly byte[] OpenSslMagic = Encoding.ASCII.GetBytes("Salted__");

    public static byte[] GenerateEcPrivatePkcs8()
    {
        using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            return ecdsa.ExportPkcs8PrivateKey();
    }

    public static string PrivateKeyToPem(byte[] pkcs8) { return ToPem("PRIVATE KEY", pkcs8); }

    public static string ExportPublicKeyPemFromPkcs8(byte[] pkcs8)
    {
        using (ECDsa ecdsa = ECDsa.Create())
        {
            ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
            return ToPem("PUBLIC KEY", ecdsa.ExportSubjectPublicKeyInfo());
        }
    }

    public static string ExportPublicKeyPemFromPem(string privatePem)
    {
        byte[] key = PemToBytes(privatePem);
        using (ECDsa ecdsa = ECDsa.Create())
        {
            try { ecdsa.ImportPkcs8PrivateKey(key, out _); }
            catch { ecdsa.ImportECPrivateKey(key, out _); }
            return ToPem("PUBLIC KEY", ecdsa.ExportSubjectPublicKeyInfo());
        }
    }

    public static string SignMessageDerBase64(string privatePem, byte[] message)
    {
        byte[] key = PemToBytes(privatePem);
        using (ECDsa ecdsa = ECDsa.Create())
        {
            try { ecdsa.ImportPkcs8PrivateKey(key, out _); }
            catch { ecdsa.ImportECPrivateKey(key, out _); }
            byte[] der = ecdsa.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            return Convert.ToBase64String(der);
        }
    }

    public static bool VerifyMessageDerBase64(string publicPem, byte[] message, string signatureB64)
    {
        if (string.IsNullOrWhiteSpace(signatureB64)) return false;
        byte[] sig;
        try { sig = Convert.FromBase64String(signatureB64.Trim()); }
        catch { return false; }
        if (sig == null || sig.Length == 0) return false;
        byte[] pub = PemToBytes(publicPem);
        using (ECDsa ecdsa = ECDsa.Create())
        {
            ecdsa.ImportSubjectPublicKeyInfo(pub, out _);
            try
            {
                return ecdsa.VerifyData(message, sig, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            }
            catch { return false; }
        }
    }

    public static string Sha256Hex(byte[] data)
    {
        using (SHA256 sha = SHA256.Create()) return BytesToHex(sha.ComputeHash(data));
    }
    public static string Sha256HexUtf8(string text) { return Sha256Hex(Encoding.UTF8.GetBytes(text ?? "")); }
    public static string HmacSha256Hex(byte[] key, byte[] message)
    {
        using (HMACSHA256 h = new HMACSHA256(key)) return BytesToHex(h.ComputeHash(message));
    }
    public static string HmacSha256HexString(string key, string message)
    {
        return HmacSha256Hex(Encoding.UTF8.GetBytes(key ?? ""), Encoding.UTF8.GetBytes(message ?? ""));
    }
    public static string DeriveMacKey(string secret, string machineId)
    {
        return HmacSha256HexString(secret, "frp-mgmt-mac-v1\n" + (machineId ?? ""));
    }

    public static string EncryptTokenPbkdf2(string token, string secret, int iterations)
    {
        if (iterations <= 0) iterations = Pbkdf2Iterations;
        byte[] salt = new byte[8];
        RandomNumberGenerator.Fill(salt);
        byte[] dk = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(secret ?? ""), salt, iterations, HashAlgorithmName.SHA256, 48);
        byte[] aesKey = new byte[32]; byte[] iv = new byte[16];
        Buffer.BlockCopy(dk, 0, aesKey, 0, 32); Buffer.BlockCopy(dk, 32, iv, 0, 16);
        byte[] ct = AesCbc(Encoding.UTF8.GetBytes(token ?? ""), aesKey, iv, true);
        byte[] packed = new byte[16 + ct.Length];
        Buffer.BlockCopy(OpenSslMagic, 0, packed, 0, 8);
        Buffer.BlockCopy(salt, 0, packed, 8, 8);
        Buffer.BlockCopy(ct, 0, packed, 16, ct.Length);
        return Convert.ToBase64String(packed);
    }

    public static string DecryptTokenPbkdf2(string ciphertextB64, string secret, int iterations)
    {
        if (iterations <= 0) iterations = Pbkdf2Iterations;
        byte[] raw = Convert.FromBase64String((ciphertextB64 ?? "").Trim());
        if (raw.Length < 16) throw new InvalidOperationException("invalid token ciphertext");
        for (int i = 0; i < 8; i++) if (raw[i] != OpenSslMagic[i]) throw new InvalidOperationException("invalid token ciphertext");
        byte[] salt = new byte[8]; Buffer.BlockCopy(raw, 8, salt, 0, 8);
        byte[] ct = new byte[raw.Length - 16]; Buffer.BlockCopy(raw, 16, ct, 0, ct.Length);
        byte[] dk = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(secret ?? ""), salt, iterations, HashAlgorithmName.SHA256, 48);
        byte[] aesKey = new byte[32]; byte[] iv = new byte[16];
        Buffer.BlockCopy(dk, 0, aesKey, 0, 32); Buffer.BlockCopy(dk, 32, iv, 0, 16);
        return Encoding.UTF8.GetString(AesCbc(ct, aesKey, iv, false));
    }

    public static string CanonicalJson(object value)
    {
        StringBuilder sb = new StringBuilder(); WriteCanonical(sb, value); return sb.ToString();
    }
    public static string NewNonceHex()
    {
        byte[] buf = new byte[32]; RandomNumberGenerator.Fill(buf); return BytesToHex(buf);
    }
    public static string NewClientIdHex()
    {
        byte[] buf = new byte[16]; RandomNumberGenerator.Fill(buf); return BytesToHex(buf);
    }

    static byte[] AesCbc(byte[] data, byte[] key, byte[] iv, bool encrypt)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = key; aes.IV = iv;
            using (ICryptoTransform xf = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                return xf.TransformFinalBlock(data, 0, data.Length);
        }
    }

    static void WriteCanonical(StringBuilder sb, object value)
    {
        if (value == null || value is DBNull) { sb.Append("null"); return; }
        if (value is bool) { sb.Append(((bool)value) ? "true" : "false"); return; }
        if (value is string) { WriteJsonString(sb, (string)value); return; }
        if (value is byte || value is sbyte || value is short || value is ushort || value is int || value is uint || value is long || value is ulong)
        { sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture)); return; }
        if (value is float || value is double || value is decimal)
        {
            double d = Convert.ToDouble(value, CultureInfo.InvariantCulture);
            if (Math.Abs(d - Math.Round(d)) < 1e-9 && !double.IsInfinity(d) && !double.IsNaN(d))
                sb.Append(((long)Math.Round(d)).ToString(CultureInfo.InvariantCulture));
            else sb.Append(d.ToString("G17", CultureInfo.InvariantCulture));
            return;
        }
        if (value is IDictionary)
        {
            IDictionary dict = (IDictionary)value;
            List<string> keys = new List<string>();
            foreach (object k in dict.Keys) keys.Add(Convert.ToString(k, CultureInfo.InvariantCulture));
            keys.Sort(StringComparer.Ordinal);
            sb.Append('{');
            for (int i = 0; i < keys.Count; i++)
            {
                if (i > 0) sb.Append(',');
                WriteJsonString(sb, keys[i]); sb.Append(':'); WriteCanonical(sb, dict[keys[i]]);
            }
            sb.Append('}'); return;
        }
        if (value is IEnumerable && !(value is string))
        {
            sb.Append('['); bool first = true;
            foreach (object item in (IEnumerable)value)
            { if (!first) sb.Append(','); first = false; WriteCanonical(sb, item); }
            sb.Append(']'); return;
        }
        WriteJsonString(sb, Convert.ToString(value, CultureInfo.InvariantCulture));
    }

    static void WriteJsonString(StringBuilder sb, string s)
    {
        sb.Append('"');
        if (s == null) { sb.Append('"'); return; }
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) { sb.Append("\\u"); sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture)); }
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    static string ToPem(string label, byte[] data)
    {
        string b64 = Convert.ToBase64String(data);
        StringBuilder sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).Append("-----\n");
        for (int i = 0; i < b64.Length; i += 64)
        {
            int len = Math.Min(64, b64.Length - i);
            sb.Append(b64, i, len).Append('\n');
        }
        sb.Append("-----END ").Append(label).Append("-----\n");
        return sb.ToString();
    }

    static byte[] PemToBytes(string pem)
    {
        if (string.IsNullOrWhiteSpace(pem)) throw new ArgumentException("empty PEM");
        string[] lines = pem.Replace("\r\n", "\n").Split('\n');
        StringBuilder b64 = new StringBuilder(); bool inside = false;
        foreach (string raw in lines)
        {
            string line = raw.Trim();
            if (line.StartsWith("-----BEGIN ")) { inside = true; continue; }
            if (line.StartsWith("-----END ")) break;
            if (inside && line.Length > 0) b64.Append(line);
        }
        return Convert.FromBase64String(b64.ToString());
    }

    static string BytesToHex(byte[] data)
    {
        char[] c = new char[data.Length * 2];
        for (int i = 0; i < data.Length; i++)
        {
            int hi = (data[i] >> 4) & 0xf; int lo = data[i] & 0xf;
            c[i * 2] = (char)(hi < 10 ? '0' + hi : 'a' + (hi - 10));
            c[i * 2 + 1] = (char)(lo < 10 ? '0' + lo : 'a' + (lo - 10));
        }
        return new string(c);
    }
}
'@

    try {
        Add-Type -TypeDefinition $modern -Language CSharp -ErrorAction Stop | Out-Null
        $script:FrpCryptoTypeReady = $true
        return
    } catch {
        if ($_.Exception.Message -match 'FrpCryptoNative|already exists') {
            $script:FrpCryptoTypeReady = $true
            return
        }
        $script:FrpCryptoModernError = $_.Exception.Message
    }

    # Framework / PS 5.1 fallback: CNG + IEEE→DER + manual PBKDF2 + manual P-256 SPKI
    $legacy = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public static class FrpCryptoNative
{
    public const int Pbkdf2Iterations = 200000;
    public static readonly byte[] OpenSslMagic = Encoding.ASCII.GetBytes("Salted__");
    // ecPublicKey + prime256v1 AlgorithmIdentifier
    static readonly byte[] P256SpkiPrefix = new byte[] {
        0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
        0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00
    };

    public static byte[] GenerateEcPrivatePkcs8()
    {
        CngKeyCreationParameters p = new CngKeyCreationParameters();
        p.ExportPolicy = CngExportPolicies.AllowPlaintextExport;
        using (CngKey key = CngKey.Create(CngAlgorithm.ECDsaP256, null, p))
        {
            return key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
        }
    }

    public static string PrivateKeyToPem(byte[] pkcs8) { return ToPem("PRIVATE KEY", pkcs8); }

    public static string ExportPublicKeyPemFromPkcs8(byte[] pkcs8)
    {
        using (CngKey key = CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob))
        using (ECDsaCng ecdsa = new ECDsaCng(key))
        {
            return ToPem("PUBLIC KEY", EccPublicToSpki(ecdsa.Key.Export(CngKeyBlobFormat.EccPublicBlob)));
        }
    }

    public static string ExportPublicKeyPemFromPem(string privatePem)
    {
        byte[] keyBytes = PemToBytes(privatePem);
        using (CngKey key = CngKey.Import(keyBytes, CngKeyBlobFormat.Pkcs8PrivateBlob))
        using (ECDsaCng ecdsa = new ECDsaCng(key))
        {
            return ToPem("PUBLIC KEY", EccPublicToSpki(ecdsa.Key.Export(CngKeyBlobFormat.EccPublicBlob)));
        }
    }

    public static string SignMessageDerBase64(string privatePem, byte[] message)
    {
        byte[] keyBytes = PemToBytes(privatePem);
        using (CngKey key = CngKey.Import(keyBytes, CngKeyBlobFormat.Pkcs8PrivateBlob))
        using (ECDsaCng ecdsa = new ECDsaCng(key))
        {
            byte[] ieee = ecdsa.SignData(message, HashAlgorithmName.SHA256);
            return Convert.ToBase64String(Ieee1363ToDer(ieee));
        }
    }

    public static bool VerifyMessageDerBase64(string publicPem, byte[] message, string signatureB64)
    {
        if (string.IsNullOrWhiteSpace(signatureB64)) return false;
        byte[] sig;
        try { sig = Convert.FromBase64String(signatureB64.Trim()); } catch { return false; }
        byte[] spki = PemToBytes(publicPem);
        byte[] ecc = SpkiToEccPublic(spki);
        using (CngKey key = CngKey.Import(ecc, CngKeyBlobFormat.EccPublicBlob))
        using (ECDsaCng ecdsa = new ECDsaCng(key))
        {
            try
            {
                byte[] ieee = DerToIeee1363(sig, 256);
                return ecdsa.VerifyData(message, ieee, HashAlgorithmName.SHA256);
            }
            catch { return false; }
        }
    }

    public static string Sha256Hex(byte[] data) { using (SHA256 sha = SHA256.Create()) return BytesToHex(sha.ComputeHash(data)); }
    public static string Sha256HexUtf8(string text) { return Sha256Hex(Encoding.UTF8.GetBytes(text ?? "")); }
    public static string HmacSha256Hex(byte[] key, byte[] message) { using (HMACSHA256 h = new HMACSHA256(key)) return BytesToHex(h.ComputeHash(message)); }
    public static string HmacSha256HexString(string key, string message) { return HmacSha256Hex(Encoding.UTF8.GetBytes(key ?? ""), Encoding.UTF8.GetBytes(message ?? "")); }
    public static string DeriveMacKey(string secret, string machineId) { return HmacSha256HexString(secret, "frp-mgmt-mac-v1\n" + (machineId ?? "")); }

    public static string EncryptTokenPbkdf2(string token, string secret, int iterations)
    {
        if (iterations <= 0) iterations = Pbkdf2Iterations;
        byte[] salt = new byte[8];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(salt);
        byte[] dk = Pbkdf2Manual(Encoding.UTF8.GetBytes(secret ?? ""), salt, iterations, 48);
        byte[] aesKey = new byte[32]; byte[] iv = new byte[16];
        Buffer.BlockCopy(dk, 0, aesKey, 0, 32); Buffer.BlockCopy(dk, 32, iv, 0, 16);
        byte[] ct = AesCbc(Encoding.UTF8.GetBytes(token ?? ""), aesKey, iv, true);
        byte[] packed = new byte[16 + ct.Length];
        Buffer.BlockCopy(OpenSslMagic, 0, packed, 0, 8); Buffer.BlockCopy(salt, 0, packed, 8, 8); Buffer.BlockCopy(ct, 0, packed, 16, ct.Length);
        return Convert.ToBase64String(packed);
    }

    public static string DecryptTokenPbkdf2(string ciphertextB64, string secret, int iterations)
    {
        if (iterations <= 0) iterations = Pbkdf2Iterations;
        byte[] raw = Convert.FromBase64String((ciphertextB64 ?? "").Trim());
        if (raw.Length < 16) throw new InvalidOperationException("invalid token ciphertext");
        for (int i = 0; i < 8; i++) if (raw[i] != OpenSslMagic[i]) throw new InvalidOperationException("invalid token ciphertext");
        byte[] salt = new byte[8]; Buffer.BlockCopy(raw, 8, salt, 0, 8);
        byte[] ct = new byte[raw.Length - 16]; Buffer.BlockCopy(raw, 16, ct, 0, ct.Length);
        byte[] dk = Pbkdf2Manual(Encoding.UTF8.GetBytes(secret ?? ""), salt, iterations, 48);
        byte[] aesKey = new byte[32]; byte[] iv = new byte[16];
        Buffer.BlockCopy(dk, 0, aesKey, 0, 32); Buffer.BlockCopy(dk, 32, iv, 0, 16);
        return Encoding.UTF8.GetString(AesCbc(ct, aesKey, iv, false));
    }

    public static string CanonicalJson(object value) { StringBuilder sb = new StringBuilder(); WriteCanonical(sb, value); return sb.ToString(); }
    public static string NewNonceHex() { byte[] buf = new byte[32]; using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(buf); return BytesToHex(buf); }
    public static string NewClientIdHex() { byte[] buf = new byte[16]; using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(buf); return BytesToHex(buf); }

    static byte[] EccPublicToSpki(byte[] eccBlob)
    {
        // BCRYPT_ECCPUBLIC_BLOB: magic(4) + cbKey(4) + X + Y
        if (eccBlob == null || eccBlob.Length < 8) throw new InvalidOperationException("bad ECC public blob");
        int cbKey = BitConverter.ToInt32(eccBlob, 4);
        byte[] point = new byte[1 + cbKey + cbKey];
        point[0] = 0x04;
        Buffer.BlockCopy(eccBlob, 8, point, 1, cbKey);
        Buffer.BlockCopy(eccBlob, 8 + cbKey, point, 1 + cbKey, cbKey);
        byte[] spki = new byte[P256SpkiPrefix.Length + point.Length];
        Buffer.BlockCopy(P256SpkiPrefix, 0, spki, 0, P256SpkiPrefix.Length);
        Buffer.BlockCopy(point, 0, spki, P256SpkiPrefix.Length, point.Length);
        return spki;
    }

    static byte[] SpkiToEccPublic(byte[] spki)
    {
        // Find uncompressed point 0x04 + 64 bytes near the end.
        if (spki == null || spki.Length < 65) throw new InvalidOperationException("bad SPKI");
        int idx = -1;
        for (int i = spki.Length - 65; i >= 0; i--) { if (spki[i] == 0x04) { idx = i; break; } }
        if (idx < 0) throw new InvalidOperationException("SPKI point not found");
        byte[] x = new byte[32]; byte[] y = new byte[32];
        Buffer.BlockCopy(spki, idx + 1, x, 0, 32);
        Buffer.BlockCopy(spki, idx + 33, y, 0, 32);
        byte[] blob = new byte[8 + 64];
        // BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345 'ECS1'
        Buffer.BlockCopy(BitConverter.GetBytes(0x31534345), 0, blob, 0, 4);
        Buffer.BlockCopy(BitConverter.GetBytes(32), 0, blob, 4, 4);
        Buffer.BlockCopy(x, 0, blob, 8, 32);
        Buffer.BlockCopy(y, 0, blob, 40, 32);
        return blob;
    }

    static byte[] Pbkdf2Manual(byte[] password, byte[] salt, int iterations, int dkLen)
    {
        int hashLen = 32; int blocks = (dkLen + hashLen - 1) / hashLen; byte[] result = new byte[dkLen];
        for (int block = 1; block <= blocks; block++)
        {
            byte[] blockBytes = BitConverter.GetBytes(System.Net.IPAddress.HostToNetworkOrder(block));
            byte[] u = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, u, 0, salt.Length); Buffer.BlockCopy(blockBytes, 0, u, salt.Length, 4);
            byte[] t; using (HMACSHA256 h = new HMACSHA256(password)) t = h.ComputeHash(u);
            byte[] acc = (byte[])t.Clone();
            for (int i = 1; i < iterations; i++)
            {
                using (HMACSHA256 h = new HMACSHA256(password)) t = h.ComputeHash(t);
                for (int j = 0; j < acc.Length; j++) acc[j] ^= t[j];
            }
            int offset = (block - 1) * hashLen; int take = Math.Min(hashLen, dkLen - offset);
            Buffer.BlockCopy(acc, 0, result, offset, take);
        }
        return result;
    }

    static byte[] AesCbc(byte[] data, byte[] key, byte[] iv, bool encrypt)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = key; aes.IV = iv;
            using (ICryptoTransform xf = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                return xf.TransformFinalBlock(data, 0, data.Length);
        }
    }

    static byte[] Ieee1363ToDer(byte[] ieee)
    {
        int half = ieee.Length / 2;
        byte[] r = TrimInt(ieee, 0, half); byte[] s = TrimInt(ieee, half, half);
        using (MemoryStream body = new MemoryStream())
        {
            WriteInt(body, r); WriteInt(body, s); byte[] inner = body.ToArray();
            using (MemoryStream ms = new MemoryStream())
            { ms.WriteByte(0x30); WriteLen(ms, inner.Length); ms.Write(inner, 0, inner.Length); return ms.ToArray(); }
        }
    }
    static byte[] DerToIeee1363(byte[] der, int keyBits)
    {
        int half = (keyBits + 7) / 8; int idx = 0;
        if (der[idx++] != 0x30) throw new InvalidOperationException("bad DER");
        ReadLen(der, ref idx);
        byte[] r = ReadInt(der, ref idx); byte[] s = ReadInt(der, ref idx);
        byte[] ieee = new byte[half * 2]; CopyRight(r, ieee, 0, half); CopyRight(s, ieee, half, half); return ieee;
    }
    static byte[] TrimInt(byte[] src, int offset, int len)
    {
        int start = offset, end = offset + len;
        while (start < end - 1 && src[start] == 0) start++;
        byte[] o = new byte[end - start]; Buffer.BlockCopy(src, start, o, 0, o.Length); return o;
    }
    static void WriteInt(Stream s, byte[] value)
    {
        s.WriteByte(0x02); bool pad = value.Length > 0 && (value[0] & 0x80) != 0;
        int len = value.Length + (pad ? 1 : 0); WriteLen(s, len); if (pad) s.WriteByte(0); s.Write(value, 0, value.Length);
    }
    static void WriteLen(Stream s, int length)
    {
        if (length < 0x80) { s.WriteByte((byte)length); return; }
        if (length < 0x100) { s.WriteByte(0x81); s.WriteByte((byte)length); return; }
        s.WriteByte(0x82); s.WriteByte((byte)((length >> 8) & 0xff)); s.WriteByte((byte)(length & 0xff));
    }
    static int ReadLen(byte[] data, ref int idx)
    {
        int b = data[idx++]; if ((b & 0x80) == 0) return b;
        int n = b & 0x7f; int len = 0; for (int i = 0; i < n; i++) len = (len << 8) | data[idx++]; return len;
    }
    static byte[] ReadInt(byte[] data, ref int idx)
    {
        if (data[idx++] != 0x02) throw new InvalidOperationException("expected INTEGER");
        int len = ReadLen(data, ref idx); byte[] v = new byte[len]; Buffer.BlockCopy(data, idx, v, 0, len); idx += len;
        int start = 0; while (start < v.Length - 1 && v[start] == 0) start++;
        if (start == 0) return v; byte[] t = new byte[v.Length - start]; Buffer.BlockCopy(v, start, t, 0, t.Length); return t;
    }
    static void CopyRight(byte[] src, byte[] dest, int destOffset, int len)
    {
        int pad = len - src.Length; for (int i = 0; i < pad; i++) dest[destOffset + i] = 0;
        Buffer.BlockCopy(src, 0, dest, destOffset + pad, src.Length);
    }

    static void WriteCanonical(StringBuilder sb, object value)
    {
        if (value == null || value is DBNull) { sb.Append("null"); return; }
        if (value is bool) { sb.Append(((bool)value) ? "true" : "false"); return; }
        if (value is string) { WriteJsonString(sb, (string)value); return; }
        if (value is byte || value is sbyte || value is short || value is ushort || value is int || value is uint || value is long || value is ulong)
        { sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture)); return; }
        if (value is float || value is double || value is decimal)
        {
            double d = Convert.ToDouble(value, CultureInfo.InvariantCulture);
            if (Math.Abs(d - Math.Round(d)) < 1e-9 && !double.IsInfinity(d) && !double.IsNaN(d))
                sb.Append(((long)Math.Round(d)).ToString(CultureInfo.InvariantCulture));
            else sb.Append(d.ToString("G17", CultureInfo.InvariantCulture));
            return;
        }
        if (value is IDictionary)
        {
            IDictionary dict = (IDictionary)value; List<string> keys = new List<string>();
            foreach (object k in dict.Keys) keys.Add(Convert.ToString(k, CultureInfo.InvariantCulture));
            keys.Sort(StringComparer.Ordinal); sb.Append('{');
            for (int i = 0; i < keys.Count; i++) { if (i > 0) sb.Append(','); WriteJsonString(sb, keys[i]); sb.Append(':'); WriteCanonical(sb, dict[keys[i]]); }
            sb.Append('}'); return;
        }
        if (value is IEnumerable && !(value is string))
        {
            sb.Append('['); bool first = true;
            foreach (object item in (IEnumerable)value) { if (!first) sb.Append(','); first = false; WriteCanonical(sb, item); }
            sb.Append(']'); return;
        }
        WriteJsonString(sb, Convert.ToString(value, CultureInfo.InvariantCulture));
    }
    static void WriteJsonString(StringBuilder sb, string s)
    {
        sb.Append('"'); if (s == null) { sb.Append('"'); return; }
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break; case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break; case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break; case '\r': sb.Append("\\r"); break; case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) { sb.Append("\\u"); sb.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture)); }
                    else sb.Append(c); break;
            }
        }
        sb.Append('"');
    }
    static string ToPem(string label, byte[] data)
    {
        string b64 = Convert.ToBase64String(data); StringBuilder sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).Append("-----\n");
        for (int i = 0; i < b64.Length; i += 64) { int len = Math.Min(64, b64.Length - i); sb.Append(b64, i, len).Append('\n'); }
        sb.Append("-----END ").Append(label).Append("-----\n"); return sb.ToString();
    }
    static byte[] PemToBytes(string pem)
    {
        string[] lines = pem.Replace("\r\n", "\n").Split('\n'); StringBuilder b64 = new StringBuilder(); bool inside = false;
        foreach (string raw in lines)
        {
            string line = raw.Trim();
            if (line.StartsWith("-----BEGIN ")) { inside = true; continue; }
            if (line.StartsWith("-----END ")) break;
            if (inside && line.Length > 0) b64.Append(line);
        }
        return Convert.FromBase64String(b64.ToString());
    }
    static string BytesToHex(byte[] data)
    {
        char[] c = new char[data.Length * 2];
        for (int i = 0; i < data.Length; i++)
        {
            int hi = (data[i] >> 4) & 0xf; int lo = data[i] & 0xf;
            c[i * 2] = (char)(hi < 10 ? '0' + hi : 'a' + (hi - 10));
            c[i * 2 + 1] = (char)(lo < 10 ? '0' + lo : 'a' + (lo - 10));
        }
        return new string(c);
    }
}
'@

    try {
        Add-Type -TypeDefinition $legacy -Language CSharp -ReferencedAssemblies @('System.Core') -ErrorAction Stop | Out-Null
        $script:FrpCryptoTypeReady = $true
    } catch {
        if ($_.Exception.Message -match 'FrpCryptoNative|already exists') {
            $script:FrpCryptoTypeReady = $true
            return
        }
        throw ("ERROR: failed to load FrpCrypto helpers. modern=[" + $script:FrpCryptoModernError + "] legacy=[" + $_.Exception.Message + "]")
    }
}

function ConvertTo-FrpPlainObject {
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string] -or $InputObject -is [bool] -or $InputObject -is [ValueType]) { return $InputObject }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $ht = New-Object 'System.Collections.Hashtable'
        foreach ($k in $InputObject.Keys) { $ht[[string]$k] = ConvertTo-FrpPlainObject $InputObject[$k] }
        return $ht
    }
    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $typeName = $InputObject.GetType().FullName
        if ($typeName -ne 'System.Management.Automation.PSCustomObject') {
            $list = New-Object 'System.Collections.ArrayList'
            foreach ($item in $InputObject) { [void]$list.Add((ConvertTo-FrpPlainObject $item)) }
            return ,$list.ToArray()
        }
    }
    if ($InputObject.PSObject -and $InputObject.PSObject.Properties) {
        $ht = New-Object 'System.Collections.Hashtable'
        foreach ($p in $InputObject.PSObject.Properties) {
            if ($p.MemberType -match 'NoteProperty|Property') {
                $ht[$p.Name] = ConvertTo-FrpPlainObject $p.Value
            }
        }
        if ($ht.Count -gt 0) { return $ht }
    }
    return $InputObject
}

function Get-FrpCanonicalJson {
    param([Parameter(Mandatory = $true)]$Object)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::CanonicalJson((ConvertTo-FrpPlainObject $Object))
}

function New-FrpEcdsaIdentity {
    Initialize-FrpCryptoTypes
    $pkcs8 = [FrpCryptoNative]::GenerateEcPrivatePkcs8()
    return @{
        PrivatePem = [FrpCryptoNative]::PrivateKeyToPem($pkcs8)
        PublicPem  = [FrpCryptoNative]::ExportPublicKeyPemFromPkcs8($pkcs8)
    }
}

function Get-FrpPublicKeyPem {
    param([Parameter(Mandatory = $true)][string]$PrivatePem)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::ExportPublicKeyPemFromPem($PrivatePem)
}

function Get-FrpSignedObject {
    param(
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)]$Body,
        [Parameter(Mandatory = $true)][long]$Timestamp,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [string]$Op = 'enroll'
    )
    Initialize-FrpCryptoTypes
    if ($Body -is [byte[]]) { $bodySha = [FrpCryptoNative]::Sha256Hex($Body) }
    elseif ($Body -is [string]) { $bodySha = [FrpCryptoNative]::Sha256HexUtf8($Body) }
    else { throw 'ERROR: Body must be string or byte[]' }
    return @{
        alg = 'ecdsa-p256-sha256'; body_sha256 = $bodySha; machine_id = [string]$MachineId
        nonce = ([string]$Nonce).Trim().ToLowerInvariant(); op = $Op; schema = 1; ts = [int64]$Timestamp
    }
}

function Get-FrpSignedMessage {
    param(
        [Parameter(Mandatory = $true)][string]$MachineId,
        [Parameter(Mandatory = $true)]$Body,
        [Parameter(Mandatory = $true)][long]$Timestamp,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [string]$Op = 'enroll'
    )
    $obj = Get-FrpSignedObject -MachineId $MachineId -Body $Body -Timestamp $Timestamp -Nonce $Nonce -Op $Op
    return (Get-FrpCanonicalJson -Object $obj)
}

function Protect-FrpSignMessage {
    param([Parameter(Mandatory = $true)][string]$PrivatePem, [Parameter(Mandatory = $true)][string]$Message)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::SignMessageDerBase64($PrivatePem, [System.Text.Encoding]::UTF8.GetBytes($Message))
}

function Test-FrpSignature {
    param([Parameter(Mandatory = $true)][string]$PublicPem, [Parameter(Mandatory = $true)][string]$Message, [Parameter(Mandatory = $true)][string]$SignatureBase64)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::VerifyMessageDerBase64($PublicPem, [System.Text.Encoding]::UTF8.GetBytes($Message), $SignatureBase64)
}

function Protect-FrpTokenPbkdf2 {
    param([Parameter(Mandatory = $true)][string]$Token, [Parameter(Mandatory = $true)][string]$Secret, [int]$Iterations = 200000)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::EncryptTokenPbkdf2($Token, $Secret, $Iterations)
}

function Unprotect-FrpTokenPbkdf2 {
    param([Parameter(Mandatory = $true)][string]$Ciphertext, [Parameter(Mandatory = $true)][string]$Secret, [int]$Iterations = 200000)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::DecryptTokenPbkdf2($Ciphertext, $Secret, $Iterations)
}

function Test-FrpFixedTimeEquals {
    <#
    .SYNOPSIS
      Constant-time string compare (same length required; XOR aggregate).
    #>
    param(
        [string]$Left,
        [string]$Right,
        [switch]$IgnoreCase
    )
    if ($null -eq $Left -or $null -eq $Right) { return $false }
    $a = [string]$Left
    $b = [string]$Right
    if ($IgnoreCase) {
        $a = $a.ToLowerInvariant()
        $b = $b.ToLowerInvariant()
    }
    if ($a.Length -ne $b.Length) { return $false }
    $diff = 0
    for ($i = 0; $i -lt $a.Length; $i++) {
        $diff = $diff -bor ([int][char]$a[$i] -bxor [int][char]$b[$i])
    }
    return ($diff -eq 0)
}

function Get-FrpHmacHex {
    param([Parameter(Mandatory = $true)][string]$Secret, [Parameter(Mandatory = $true)][string]$Message)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::HmacSha256HexString($Secret, $Message)
}

function Get-FrpDerivedMacKey {
    param([Parameter(Mandatory = $true)][string]$Secret, [Parameter(Mandatory = $true)][string]$MachineId)
    Initialize-FrpCryptoTypes
    return [FrpCryptoNative]::DeriveMacKey($Secret, $MachineId)
}

function Get-FrpEnrollmentSignature {
    param([Parameter(Mandatory = $true)][string]$Secret, [Parameter(Mandatory = $true)][string]$Timestamp, [Parameter(Mandatory = $true)][string]$Body)
    return Get-FrpHmacHex -Secret $Secret -Message ("${Timestamp}`n${Body}")
}

function New-FrpNonce { Initialize-FrpCryptoTypes; return [FrpCryptoNative]::NewNonceHex() }
function New-FrpClientId { Initialize-FrpCryptoTypes; return [FrpCryptoNative]::NewClientIdHex() }
function Get-FrpSha256Hex { param([Parameter(Mandatory = $true)][byte[]]$Bytes); Initialize-FrpCryptoTypes; return [FrpCryptoNative]::Sha256Hex($Bytes) }
function Get-FrpSha256HexOfFile { param([Parameter(Mandatory = $true)][string]$Path); return Get-FrpSha256Hex -Bytes ([System.IO.File]::ReadAllBytes($Path)) }
