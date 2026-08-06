using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10

namespace PostQuantum.MlDsa
{
    /// <summary>
    /// Represents an ML-DSA (Module-Lattice-Based Digital Signature Algorithm) key for
    /// post-quantum cryptography. Supports the ML-DSA-44, ML-DSA-65 and ML-DSA-87 parameter
    /// sets defined in NIST FIPS 204, over the native .NET
    /// <see cref="System.Security.Cryptography.MLDsa"/> implementation.
    /// </summary>
    /// <remarks>
    /// Two signing back-ends are supported behind one API:
    /// <list type="bullet">
    ///   <item><b>Software</b> keys use the managed <see cref="System.Security.Cryptography.MLDsa"/> APIs.</item>
    ///   <item><b>Hardware</b> keys (non-exportable <see cref="CngKey"/>, e.g. an HSM) sign through the
    ///   CNG provider via CngHandleSigner - the private key never leaves the device.</item>
    /// </list>
    /// </remarks>
    public class MlDsaKey : IDisposable
    {
        private System.Security.Cryptography.MLDsa? mldsaAlgorithm;
        private byte[]? publicKey;
        private byte[]? privateKey;
        private CngKey? cngKeyHandle; // For non-exportable HSM keys

        // ML-DSA algorithm OIDs as defined in NIST FIPS 204 / the CSOR registry.
        private static readonly string OidMlDsa44 = "2.16.840.1.101.3.4.3.17";
        private static readonly string OidMlDsa65 = "2.16.840.1.101.3.4.3.18";
        private static readonly string OidMlDsa87 = "2.16.840.1.101.3.4.3.19";

        /// <summary>True when private key material (or an HSM private key) is available for signing.</summary>
        public bool HasPrivate { get; private set; }

        /// <summary>The ML-DSA parameter set of this key.</summary>
        public MlDsaParameterSet ParameterSet { get; private set; }

        /// <summary>A caller-assigned identifier (file path, certificate subject, key name, etc.).</summary>
        public string? Id { get; set; }

        /// <summary>Public key size in bytes for this parameter set (FIPS 204).</summary>
        public int PublicKeySize => GetPublicKeySize(ParameterSet);

        /// <summary>Private key size in bytes for this parameter set (FIPS 204).</summary>
        public int PrivateKeySize => GetPrivateKeySize(ParameterSet);

        /// <summary>Signature size in bytes for this parameter set (FIPS 204).</summary>
        public int SignatureSize => GetSignatureSize(ParameterSet);

        /// <summary>NIST security level (2, 3 or 5) for this parameter set.</summary>
        public int SecurityLevel => GetSecurityLevel(ParameterSet);

        /// <summary>The canonical algorithm name, e.g. "ML-DSA-87".</summary>
        public string AlgorithmName => $"ML-DSA-{ParameterSet.ToString().Replace("ML_DSA_", "")}";

        /// <summary>The algorithm OID for this parameter set.</summary>
        public string AlgorithmOid => GetAlgorithmOid(ParameterSet);

        /// <summary>Creates an ML-DSA key from a file (PEM, DER, or certificate).</summary>
        public MlDsaKey(string filePath)
        {
            Id = filePath;
            LoadFromFile(filePath);
        }

        /// <summary>Creates an ML-DSA key from raw key bytes (PKCS#8 private or SubjectPublicKeyInfo).</summary>
        public MlDsaKey(byte[] keyBytes, MlDsaParameterSet parameterSet, bool isPrivate)
        {
            HasPrivate = isPrivate;

            if (isPrivate)
            {
                mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportPkcs8PrivateKey(keyBytes);
                privateKey = keyBytes.ToArray<byte>();
                publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();
            }
            else
            {
                mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(keyBytes);
                publicKey = keyBytes;
            }

            ParameterSet = ResolveParameterSetFromAlgorithm();

            if (ParameterSet != parameterSet)
                throw new MlDsaException(
                    MlDsaErrorCode.InvalidArgument,
                    $"Supplied parameterSet '{parameterSet}' does not match imported key algorithm '{mldsaAlgorithm!.Algorithm.Name}'.");
        }

        /// <summary>
        /// Creates an ML-DSA key backed by a non-exportable CNG key (e.g. an HSM key).
        /// Signing is performed through the CNG provider, not via exported key material.
        /// </summary>
        [SupportedOSPlatform("windows")]
        public MlDsaKey(CngKey cngKey, MlDsaParameterSet parameterSet)
        {
            cngKeyHandle = cngKey;
            ParameterSet = parameterSet;
            HasPrivate = true; // HSM holds the private key
            Id = cngKey.KeyName;

            try
            {
                publicKey = cngKey.Export(CngKeyBlobFormat.GenericPublicBlob);
            }
            catch (CryptographicException)
            {
                publicKey = null;
            }
        }

        /// <summary>
        /// Creates an ML-DSA public key from an <see cref="X509Certificate2"/> containing an ML-DSA
        /// public key. The certificate's algorithm OID selects the parameter set.
        /// </summary>
        public MlDsaKey(X509Certificate2 certificate)
        {
            if (certificate == null)
                throw new MlDsaException("Certificate cannot be null.");

            Id = certificate.Subject;

            var algorithmOid = certificate.PublicKey.Oid?.Value;
            ParameterSet = algorithmOid switch
            {
                var oid when oid == OidMlDsa44 => MlDsaParameterSet.ML_DSA_44,
                var oid when oid == OidMlDsa65 => MlDsaParameterSet.ML_DSA_65,
                var oid when oid == OidMlDsa87 => MlDsaParameterSet.ML_DSA_87,
                _ => throw new MlDsaException($"Certificate does not contain an ML-DSA key. Algorithm OID: {algorithmOid ?? "null"}")
            };

            HasPrivate = false;

            var spkiBytes = certificate.PublicKey.ExportSubjectPublicKeyInfo();
            mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(spkiBytes);
            publicKey = spkiBytes;
        }

        private MlDsaKey(System.Security.Cryptography.MLDsa algorithm, MlDsaParameterSet parameterSet, bool hasPrivate)
        {
            mldsaAlgorithm = algorithm;
            ParameterSet = parameterSet;
            HasPrivate = hasPrivate;

            publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();
            if (hasPrivate)
            {
                privateKey = mldsaAlgorithm.ExportPkcs8PrivateKey();
            }
        }

        /// <summary>Generates a new ML-DSA key pair for the given parameter set.</summary>
        public static MlDsaKey Generate(MlDsaParameterSet parameterSet)
        {
            var mldsaParams = ConvertParameterSet(parameterSet);
            var algorithm = System.Security.Cryptography.MLDsa.GenerateKey(mldsaParams);
            return new MlDsaKey(algorithm, parameterSet, true);
        }

        /// <summary>Loads an ML-DSA public key from a certificate file (.cer, .crt, .pem).</summary>
        public static MlDsaKey FromCertificate(string certPath)
        {
            if (!File.Exists(certPath))
                throw new MlDsaException($"Certificate file not found: {certPath}");

            using X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
            var key = new MlDsaKey(cert);
            key.Id = certPath;
            return key;
        }

        /// <summary>Returns true when the given certificate carries an ML-DSA public key.</summary>
        public static bool IsMlDsaCertificate(X509Certificate2 certificate)
        {
            if (certificate == null)
                return false;

            var algorithmOid = certificate.PublicKey.Oid?.Value;
            return algorithmOid == OidMlDsa44
                || algorithmOid == OidMlDsa65
                || algorithmOid == OidMlDsa87;
        }

        /// <summary>Gets the ML-DSA algorithm OID for the given parameter set.</summary>
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

        /// <summary>
        /// Signs a message with the ML-DSA private key. ML-DSA signs the message directly
        /// (no external pre-hash). HSM-backed keys sign through the CNG provider.
        /// </summary>
        public byte[] SignHash(byte[] data)
        {
            if (!HasPrivate)
                throw new MlDsaException("Private key is not available for signing.");

            if (cngKeyHandle != null && OperatingSystem.IsWindows())
                return SignViaCngHandle(data);

            if (mldsaAlgorithm == null)
                throw new MlDsaException(
                    "No signing key material is available: the key has neither a CNG/HSM handle nor an in-memory ML-DSA algorithm object.");

            return mldsaAlgorithm.SignData(data, context: null);
        }

        [SupportedOSPlatform("windows")]
        private byte[] SignViaCngHandle(byte[] data)
        {
            var signature = CngHandleSigner.Sign(cngKeyHandle!, data);
            return signature.ToArray();
        }

        /// <summary>
        /// Verifies an ML-DSA signature over the given data. Never throws: any failure
        /// (invalid signature, unsupported provider, missing key material) returns false.
        /// </summary>
        public bool VerifySignature(byte[] data, byte[] signature)
        {
            try
            {
                if (mldsaAlgorithm != null)
                    return mldsaAlgorithm.VerifyData(data, signature, context: null);

                if (cngKeyHandle != null && OperatingSystem.IsWindows())
                    return CngHandleSigner.Verify(cngKeyHandle, data, signature);

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Returns the public key material (SPKI, or the CNG public blob for HSM keys), or null.</summary>
        public byte[]? ExportPublicKey() => publicKey?.ToArray();

        /// <summary>Exports the SubjectPublicKeyInfo, or throws for non-exportable HSM keys with no in-memory object.</summary>
        public byte[] ExportSubjectPublicKeyInfo()
        {
            if (mldsaAlgorithm == null)
                throw new MlDsaException(
                    "SubjectPublicKeyInfo is not available: this is a non-exportable HSM-backed key with no in-memory ML-DSA object. " +
                    "Source the SPKI from the signing certificate instead.");
            return mldsaAlgorithm.ExportSubjectPublicKeyInfo();
        }

        /// <summary>Exports the PKCS#8 private key. Throws when no exportable private key is available.</summary>
        public byte[] ExportPkcs8PrivateKey()
        {
            if (!HasPrivate || mldsaAlgorithm == null)
                throw new MlDsaException(
                    MlDsaErrorCode.ExportFailed,
                    "No exportable private key is available (public-only, or a non-exportable HSM key).");
            return mldsaAlgorithm.ExportPkcs8PrivateKey();
        }

        private void LoadFromFile(string filePath)
        {
            if (!File.Exists(filePath))
                throw new MlDsaException($"Key file not found: {filePath}");

            var extension = Path.GetExtension(filePath).ToLower();

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
            X509Certificate2 cert = X509CertificateLoader.LoadCertificateFromFile(certPath);
            if (!IsMlDsaCertificate(cert))
                throw new MlDsaException($"Certificate does not contain an ML-DSA key. Algorithm OID: {cert.PublicKey.Oid?.Value ?? "null"}");

            var algorithmOid = cert.PublicKey.Oid!.Value;
            ParameterSet = algorithmOid switch
            {
                var oid when oid == OidMlDsa44 => MlDsaParameterSet.ML_DSA_44,
                var oid when oid == OidMlDsa65 => MlDsaParameterSet.ML_DSA_65,
                var oid when oid == OidMlDsa87 => MlDsaParameterSet.ML_DSA_87,
                _ => throw new MlDsaException($"Unsupported ML-DSA algorithm OID: {algorithmOid}")
            };

            HasPrivate = false;

            var spkiBytes = cert.PublicKey.ExportSubjectPublicKeyInfo();
            mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(spkiBytes);
            publicKey = spkiBytes;
        }

        private void LoadFromPem(string filePath)
        {
            var pemContent = File.ReadAllText(filePath);

            if (pemContent.Contains("BEGIN CERTIFICATE"))
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
                }

                publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();
                ParameterSet = ResolveParameterSetFromAlgorithm();
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
                privateKey = derBytes;
                publicKey = mldsaAlgorithm.ExportSubjectPublicKeyInfo();
                ParameterSet = ResolveParameterSetFromAlgorithm();
            }
            catch (CryptographicException)
            {
                try
                {
                    mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(derBytes);
                    HasPrivate = false;
                    publicKey = derBytes;
                    ParameterSet = ResolveParameterSetFromAlgorithm();
                }
                catch (CryptographicException ex)
                {
                    throw new MlDsaException("Failed to load key from DER file. Not a valid ML-DSA private or public key.", ex);
                }
            }
        }

        private MlDsaParameterSet ResolveParameterSetFromAlgorithm()
        {
            return mldsaAlgorithm!.Algorithm.Name switch
            {
                "ML-DSA-44" => MlDsaParameterSet.ML_DSA_44,
                "ML-DSA-65" => MlDsaParameterSet.ML_DSA_65,
                "ML-DSA-87" => MlDsaParameterSet.ML_DSA_87,
                _ => throw new MlDsaException($"Unrecognized ML-DSA algorithm: {mldsaAlgorithm!.Algorithm.Name}")
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

        private static int GetPublicKeySize(MlDsaParameterSet parameterSet) => parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 1312,
            MlDsaParameterSet.ML_DSA_65 => 1952,
            MlDsaParameterSet.ML_DSA_87 => 2592,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };

        private static int GetPrivateKeySize(MlDsaParameterSet parameterSet) => parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 2560,
            MlDsaParameterSet.ML_DSA_65 => 4032,
            MlDsaParameterSet.ML_DSA_87 => 4896,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };

        private static int GetSignatureSize(MlDsaParameterSet parameterSet) => parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 2420,
            MlDsaParameterSet.ML_DSA_65 => 3309,
            MlDsaParameterSet.ML_DSA_87 => 4627,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };

        private static int GetSecurityLevel(MlDsaParameterSet parameterSet) => parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => 2,
            MlDsaParameterSet.ML_DSA_65 => 3,
            MlDsaParameterSet.ML_DSA_87 => 5,
            _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
        };

        public override string ToString()
            => $"ML-DSA Key '{Id ?? "anonymous"}' ({ParameterSet}, Security Level {SecurityLevel}, {(HasPrivate ? "Private" : "Public")})";

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                mldsaAlgorithm?.Dispose();
                cngKeyHandle?.Dispose();
            }

            if (privateKey != null)
            {
                Array.Clear(privateKey, 0, privateKey.Length);
                privateKey = null;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
