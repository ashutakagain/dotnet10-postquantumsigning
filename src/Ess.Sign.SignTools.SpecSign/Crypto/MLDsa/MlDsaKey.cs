using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Ess.Sign.SignTools.SpecSign.Context;
using Ess.Sign.SignTools.SpecSign.Expressions;

#pragma warning disable SYSLIB5006

namespace Ess.Sign.SignTools.SpecSign.Crypto.MLDsa;

public class MlDsaKey : IPropertyCapable, IDisposable
{
    private static readonly string OidMlDsa44 = "2.16.840.1.101.3.4.3.17";
    private static readonly string OidMlDsa65 = "2.16.840.1.101.3.4.3.18";
    private static readonly string OidMlDsa87 = "2.16.840.1.101.3.4.3.19";

    private System.Security.Cryptography.MLDsa? mldsaAlgorithm;
    private byte[]? publicKey;
    private byte[]? privateKey;
    private CngKey? cngKeyHandle;
    private bool publicKeyIsSubjectPublicKeyInfo = true;

    public MlDsaKey(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        Id = filePath;
        LoadFromFile(filePath);
    }

    public MlDsaKey(byte[] keyBytes, MlDsaParameterSet parameterSet, bool isPrivate)
    {
        ArgumentNullException.ThrowIfNull(keyBytes);

        HasPrivate = isPrivate;

        if (isPrivate)
        {
            mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportPkcs8PrivateKey(keyBytes);
            privateKey = keyBytes.ToArray();
            publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();
        }
        else
        {
            mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(keyBytes);
            publicKey = keyBytes.ToArray();
        }

        ParameterSet = ResolveParameterSetFromAlgorithm();

        if (ParameterSet != parameterSet)
        {
            throw new MlDsaException(
                MlDsaErrorCode.InvalidArgument,
                $"Supplied parameterSet '{parameterSet}' does not match imported key algorithm '{mldsaAlgorithm.Algorithm.Name}'.");
        }
    }

    [SupportedOSPlatform("windows")]
    public MlDsaKey(CngKey cngKey, MlDsaParameterSet parameterSet)
    {
        ArgumentNullException.ThrowIfNull(cngKey);

        cngKeyHandle = cngKey;
        ParameterSet = parameterSet;
        HasPrivate = true;
        Id = cngKey.KeyName ?? cngKey.UniqueName;

        try
        {
            publicKey = cngKey.Export(CngKeyBlobFormat.GenericPublicBlob);
            publicKeyIsSubjectPublicKeyInfo = false;
        }
        catch (CryptographicException)
        {
            publicKey = null;
        }
    }

    public MlDsaKey(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        Id = certificate.Subject;
        ParameterSet = GetParameterSetFromOid(certificate.PublicKey.Oid?.Value);
        HasPrivate = false;

        var spkiBytes = certificate.PublicKey.ExportSubjectPublicKeyInfo();
        mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(spkiBytes);
        publicKey = spkiBytes;
    }

    private MlDsaKey(System.Security.Cryptography.MLDsa algorithm, MlDsaParameterSet parameterSet, bool hasPrivate)
    {
        mldsaAlgorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        ParameterSet = parameterSet;
        HasPrivate = hasPrivate;
        publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();

        if (hasPrivate)
        {
            privateKey = mldsaAlgorithm.ExportPkcs8PrivateKey();
        }
    }

    public bool HasPrivate { get; private set; }

    public MlDsaParameterSet ParameterSet { get; private set; }

    public string? Id { get; set; }

    public int PublicKeySize => GetPublicKeySize(ParameterSet);

    public int PrivateKeySize => GetPrivateKeySize(ParameterSet);

    public int SignatureSize => GetSignatureSize(ParameterSet);

    public static MlDsaKey Generate(MlDsaParameterSet parameterSet)
    {
        var mldsaParams = ConvertParameterSet(parameterSet);
        var algorithm = System.Security.Cryptography.MLDsa.GenerateKey(mldsaParams);
        return new MlDsaKey(algorithm, parameterSet, true);
    }

    public static MlDsaKey FromCertificate(string certPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certPath);

        if (!File.Exists(certPath))
        {
            throw new MlDsaException($"Certificate file not found: {certPath}");
        }

        using var cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
        var key = new MlDsaKey(cert)
        {
            Id = certPath
        };

        return key;
    }

    public static bool IsMlDsaCertificate(X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return false;
        }

        var algorithmOid = certificate.PublicKey.Oid?.Value;
        return algorithmOid == OidMlDsa44
            || algorithmOid == OidMlDsa65
            || algorithmOid == OidMlDsa87;
    }

    public static string GetAlgorithmOid(MlDsaParameterSet parameterSet)
    {
        return parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => OidMlDsa44,
            MlDsaParameterSet.ML_DSA_65 => OidMlDsa65,
            MlDsaParameterSet.ML_DSA_87 => OidMlDsa87,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };
    }

    public byte[] SignHash(byte[] hash, NodeContext? context = null)
    {
        ArgumentNullException.ThrowIfNull(hash);

        if (!HasPrivate)
        {
            throw new MlDsaException("Private key is not available for signing.");
        }

        if (HasPlaceholderDigestContext(context))
        {
            return GetPlaceholderSignature(hash, context!);
        }

        if (cngKeyHandle is not null)
        {
            return SignViaCngHandle(hash);
        }

        if (mldsaAlgorithm is null)
        {
            throw new MlDsaException("Signing algorithm is not available.");
        }

        return mldsaAlgorithm.SignData(hash, context: null);
    }

    public bool VerifySignature(byte[] hash, byte[] signature, NodeContext? context = null)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);

        if (HasPlaceholderDigestContext(context))
        {
            var expected = GetPlaceholderSignature(hash, context!);
            return signature.SequenceEqual(expected);
        }

        if (mldsaAlgorithm is null)
        {
            throw new MlDsaException("Public key is not available for verification.");
        }

        try
        {
            return mldsaAlgorithm.VerifyData(hash, signature, context: null);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public Operand GetPropertyValue(string prop)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prop);

        prop = prop.ToLowerInvariant();

        return prop switch
        {
            "paramset" or "parameterset" => StringOperand.CreateString(ParameterSet.ToString()),
            "publickey" or "pubkey" => BlobOperand.CreateBlob(publicKey ?? Array.Empty<byte>()),
            "publickeysize" => NumericOperand.CreateNumeric(PublicKeySize),
            "privatekeysize" => NumericOperand.CreateNumeric(PrivateKeySize),
            "signaturesize" or "sigsize" => NumericOperand.CreateNumeric(SignatureSize),
            "algorithm" or "alg" => StringOperand.CreateString($"ML-DSA-{ParameterSet.ToString().Replace("ML_DSA_", string.Empty, StringComparison.Ordinal)}"),
            "securitylevel" => NumericOperand.CreateNumeric(GetSecurityLevel(ParameterSet)),
            "spki" => BlobOperand.CreateBlob(GetSubjectPublicKeyInfo()),
            "hasprivate" or "hasprivatekey" => NumericOperand.CreateNumeric(HasPrivate ? 1 : 0),
            _ => throw new MlDsaException($"Property '{prop}' is not recognized for ML-DSA keys.")
        };
    }

    public override string ToString()
    {
        return $"ML-DSA Key '{Id ?? "anonymous"}' ({ParameterSet}, Security Level {GetSecurityLevel(ParameterSet)}, {(HasPrivate ? "Private" : "Public")})";
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            mldsaAlgorithm?.Dispose();

            if (OperatingSystem.IsWindows())
            {
                cngKeyHandle?.Dispose();
            }
        }

        if (privateKey is not null)
        {
            CryptographicOperations.ZeroMemory(privateKey);
            privateKey = null;
        }
    }

    private static bool HasPlaceholderDigestContext(NodeContext? context)
    {
        return context?.NonFileContext.PlaceholderDigestPathBase is not null
            || context?.ContextGraph.NonFileContext.PlaceholderDigestPathBase is not null;
    }

    [SupportedOSPlatform("windows")]
    private byte[] SignViaCngHandle(byte[] data)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("CNG-backed ML-DSA signing is only supported on Windows.");
        }

        return CngHandleSigner.Sign(cngKeyHandle!, data);
    }

    private byte[] GetPlaceholderSignature(byte[] hash, NodeContext context)
    {
        var sig = new byte[SignatureSize];
        byte[] magic = [0x4D, 0x4C, 0x44, 0x53, 0x41, 0x00, 0x00, 0x00];

        Buffer.BlockCopy(magic, 0, sig, 0, magic.Length);
        sig[8] = (byte)ParameterSet;
        Buffer.BlockCopy(hash, 0, sig, 16, Math.Min(hash.Length, SignatureSize - 16));

        var basePath = context.ContextGraph.NonFileContext.PlaceholderDigestPathBase
            ?? context.NonFileContext.PlaceholderDigestPathBase;

        if (!string.IsNullOrEmpty(basePath))
        {
            Directory.CreateDirectory(basePath);
            var safeFileName = $"{SanitizeFileName(context.Structure.Name)}_{SanitizeFileName(Id ?? "anonymous")}.mldsa.b64";
            var digestFile = Path.Combine(basePath, safeFileName);
            File.WriteAllText(digestFile, Convert.ToBase64String(hash));
        }

        return sig;
    }

    private byte[] GetSubjectPublicKeyInfo()
    {
        if (mldsaAlgorithm is not null)
        {
            return mldsaAlgorithm.ExportSubjectPublicKeyInfo();
        }

        if (publicKeyIsSubjectPublicKeyInfo && publicKey is not null)
        {
            return publicKey.ToArray();
        }

        throw new MlDsaException("SubjectPublicKeyInfo is not available for this key.");
    }

    private void LoadFromFile(string filePath)
    {
        if (!File.Exists(filePath))
        {
            throw new MlDsaException($"Key file not found: {filePath}");
        }

        var extension = Path.GetExtension(filePath).ToLowerInvariant();

        switch (extension)
        {
            case ".pem":
                LoadFromPem(filePath);
                break;
            case ".der":
            case ".key":
                LoadFromDer(filePath);
                break;
            case ".cer":
            case ".crt":
                LoadFromCertificateFile(filePath);
                break;
            default:
                throw new MlDsaException($"Unsupported key file format: {extension}. Supported formats: .pem, .der, .key, .cer, .crt");
        }
    }

    private void LoadFromCertificateFile(string certPath)
    {
        using var cert = X509CertificateLoader.LoadCertificateFromFile(certPath);

        if (!IsMlDsaCertificate(cert))
        {
            throw new MlDsaException($"Certificate does not contain an ML-DSA key. Algorithm OID: {cert.PublicKey.Oid?.Value ?? "null"}");
        }

        ParameterSet = GetParameterSetFromOid(cert.PublicKey.Oid?.Value);
        HasPrivate = false;

        var spkiBytes = cert.PublicKey.ExportSubjectPublicKeyInfo();
        mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(spkiBytes);
        publicKey = spkiBytes;
        publicKeyIsSubjectPublicKeyInfo = true;
    }

    private void LoadFromPem(string filePath)
    {
        var pemContent = File.ReadAllText(filePath);

        if (pemContent.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal))
        {
            LoadFromCertificateFile(filePath);
            return;
        }

        try
        {
            mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportFromPem(pemContent);

            try
            {
                privateKey = mldsaAlgorithm.ExportPkcs8PrivateKey();
                HasPrivate = true;
            }
            catch (CryptographicException)
            {
                HasPrivate = false;
                privateKey = null;
            }

            publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();
            ParameterSet = ResolveParameterSetFromAlgorithm();
            publicKeyIsSubjectPublicKeyInfo = true;
        }
        catch (CryptographicException ex)
        {
            throw new MlDsaException($"Failed to import ML-DSA key from PEM file: {ex.Message}", ex);
        }
    }

    private void LoadFromDer(string filePath)
    {
        var derBytes = File.ReadAllBytes(filePath);

        try
        {
            mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportPkcs8PrivateKey(derBytes);
            HasPrivate = true;
            privateKey = derBytes.ToArray();
            publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();
            ParameterSet = ResolveParameterSetFromAlgorithm();
            publicKeyIsSubjectPublicKeyInfo = true;
        }
        catch (CryptographicException)
        {
            try
            {
                mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(derBytes);
                HasPrivate = false;
                privateKey = null;
                publicKey = derBytes.ToArray();
                ParameterSet = ResolveParameterSetFromAlgorithm();
                publicKeyIsSubjectPublicKeyInfo = true;
            }
            catch (CryptographicException ex)
            {
                throw new MlDsaException("Failed to load key from DER file. Not a valid ML-DSA private or public key.", ex);
            }
        }
    }

    private MlDsaParameterSet ResolveParameterSetFromAlgorithm()
    {
        if (mldsaAlgorithm is null)
        {
            throw new MlDsaException("ML-DSA algorithm is not available.");
        }

        return mldsaAlgorithm.Algorithm.Name switch
        {
            "ML-DSA-44" => MlDsaParameterSet.ML_DSA_44,
            "ML-DSA-65" => MlDsaParameterSet.ML_DSA_65,
            "ML-DSA-87" => MlDsaParameterSet.ML_DSA_87,
            _ => throw new MlDsaException($"Unrecognized ML-DSA algorithm: {mldsaAlgorithm.Algorithm.Name}")
        };
    }

    private static MlDsaParameterSet GetParameterSetFromOid(string? algorithmOid)
    {
        return algorithmOid switch
        {
            var oid when oid == OidMlDsa44 => MlDsaParameterSet.ML_DSA_44,
            var oid when oid == OidMlDsa65 => MlDsaParameterSet.ML_DSA_65,
            var oid when oid == OidMlDsa87 => MlDsaParameterSet.ML_DSA_87,
            _ => throw new MlDsaException($"Certificate does not contain an ML-DSA key. Algorithm OID: {algorithmOid ?? "null"}")
        };
    }

    private static MLDsaAlgorithm ConvertParameterSet(MlDsaParameterSet parameterSet)
    {
        return parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
            MlDsaParameterSet.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
            MlDsaParameterSet.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };
    }

    private static int GetPublicKeySize(MlDsaParameterSet parameterSet)
    {
        return parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 1312,
            MlDsaParameterSet.ML_DSA_65 => 1952,
            MlDsaParameterSet.ML_DSA_87 => 2592,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };
    }

    private static int GetPrivateKeySize(MlDsaParameterSet parameterSet)
    {
        return parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 2560,
            MlDsaParameterSet.ML_DSA_65 => 4032,
            MlDsaParameterSet.ML_DSA_87 => 4896,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };
    }

    private static int GetSignatureSize(MlDsaParameterSet parameterSet)
    {
        return parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 2420,
            MlDsaParameterSet.ML_DSA_65 => 3309,
            MlDsaParameterSet.ML_DSA_87 => 4627,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };
    }

    private static int GetSecurityLevel(MlDsaParameterSet parameterSet)
    {
        return parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 2,
            MlDsaParameterSet.ML_DSA_65 => 3,
            MlDsaParameterSet.ML_DSA_87 => 5,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };
    }

    private static string SanitizeFileName(string name)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        return string.Concat(name.Select(c => invalidChars.Contains(c) ? '_' : c));
    }
}

public enum MlDsaParameterSet
{
    ML_DSA_44 = 44,
    ML_DSA_65 = 65,
    ML_DSA_87 = 87
}
