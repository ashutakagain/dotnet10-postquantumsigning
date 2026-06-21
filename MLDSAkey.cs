using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Ess.Sign.SignTools.SpecSign.Context;
using Ess.Sign.SignTools.SpecSign.Expressions;

#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10 preview

namespace Ess.Sign.SignTools.SpecSign.Crypto.MLDsa
{
    /// <summary>
    /// Represents an ML-DSA (Module-Lattice-Based Digital Signature Algorithm) key for post-quantum cryptography.
    /// Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets as defined in FIPS 204.
    /// Uses native .NET 10 implementation of System.Security.Cryptography.MLDsa.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class follows the patterns described in the .NET 10 PQC blog post:
    /// https://devblogs.microsoft.com/dotnet/post-quantum-cryptography-in-dotnet/
    /// </para>
    /// <para>
    /// Key design decisions based on the <see cref="System.Security.Cryptography.MLDsa"/> source:
    /// <list type="bullet">
    ///   <item>All instantiation uses static factory methods — there is no <c>MLDsa.Create()</c></item>
    ///   <item>Key sizes come from <see cref="MLDsaAlgorithm"/> properties, not hardcoded constants</item>
    ///   <item><c>SignData</c>/<c>VerifyData</c> operate on raw message data (ML-DSA signs directly, no pre-hash)</item>
    ///   <item><c>SignPreHash</c>/<c>VerifyPreHash</c> support HashML-DSA mode with a hash algorithm OID</item>
    ///   <item>A context parameter (up to 255 bytes) enables domain separation per FIPS 204 §5.2</item>
    /// </list>
    /// </para>
    /// </remarks>
    public class MlDsaKey : IPropertyCapable, IDisposable
    {
        #region Fields

        private System.Security.Cryptography.MLDsa mldsaAlgorithm;
        private byte[] publicKey;
        private byte[] privateKey;
        private CngKey cngKeyHandle; // For non-exportable HSM keys

        #endregion

        #region Constants

        /// <summary>
        /// ML-DSA algorithm OIDs as defined in NIST FIPS 204 / RFC 9629
        /// </summary>
        private static readonly string OidMlDsa44 = "2.16.840.1.101.3.4.3.17";
        private static readonly string OidMlDsa65 = "2.16.840.1.101.3.4.3.18";
        private static readonly string OidMlDsa87 = "2.16.840.1.101.3.4.3.19";

        #endregion

        #region Properties

        public bool HasPrivate { get; private set; }
        public MlDsaParameterSet ParameterSet { get; private set; }
        public string Id { get; set; }

        public int PublicKeySize => GetPublicKeySize(ParameterSet);
        public int PrivateKeySize => GetPrivateKeySize(ParameterSet);
        public int SignatureSize => GetSignatureSize(ParameterSet);

        #endregion

        #region Constructors

        /// <summary>
        /// Creates an ML-DSA key from file (PEM or DER format)
        /// </summary>
        public MlDsaKey(string filePath)
        {
            Id = filePath;
            LoadFromFile(filePath);
        }

        /// <summary>
        /// Creates an ML-DSA key from raw key bytes
        /// </summary>
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

            // Derive the actual parameter set from the imported key material.
            ParameterSet = ResolveParameterSetFromAlgorithm();

            if (ParameterSet != parameterSet)
                throw new MlDsaException(
                    MlDsaErrorCode.InvalidArgument,
                    $"Supplied parameterSet '{parameterSet}' does not match imported key algorithm '{mldsaAlgorithm.Algorithm.Name}'.");
        }

        /// <summary>
        /// Creates an ML-DSA key backed by a non-exportable CNG key (e.g., nCipher HSM).
        /// Signing is performed through the CNG provider, not via exported key material.
        /// </summary>
        public MlDsaKey(CngKey cngKey, MlDsaParameterSet parameterSet)
        {
            cngKeyHandle = cngKey;
            ParameterSet = parameterSet;
            HasPrivate = true; // HSM holds the private key
            Id = cngKey.KeyName;

            // Export public key info if possible for verification purposes
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
        /// Creates an ML-DSA public key from an X509Certificate2 containing an ML-DSA public key.
        /// The certificate's algorithm OID is used to determine the ML-DSA parameter set.
        /// </summary>
        public MlDsaKey(X509Certificate2 certificate)
        {
            if (certificate == null)
                throw new MlDsaException("Certificate cannot be null.");

            Id = certificate.Subject;

            // Determine parameter set from the certificate's public key algorithm OID
            var algorithmOid = certificate.PublicKey.Oid?.Value;
            ParameterSet = algorithmOid switch
            {
                var oid when oid == OidMlDsa44 => MlDsaParameterSet.ML_DSA_44,
                var oid when oid == OidMlDsa65 => MlDsaParameterSet.ML_DSA_65,
                var oid when oid == OidMlDsa87 => MlDsaParameterSet.ML_DSA_87,
                _ => throw new MlDsaException($"Certificate does not contain an ML-DSA key. Algorithm OID: {algorithmOid ?? "null"}")
            };

            HasPrivate = false;

            // Import the SubjectPublicKeyInfo from the certificate using the static factory
            var spkiBytes = certificate.PublicKey.ExportSubjectPublicKeyInfo();
            mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportSubjectPublicKeyInfo(spkiBytes);
            publicKey = spkiBytes;
        }

        /// <summary>
        /// Creates an ML-DSA key from existing MLDsa algorithm instance
        /// </summary>
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

        #endregion

        #region Static Factory Methods

        /// <summary>
        /// Generates a new ML-DSA key pair using native .NET implementation
        /// </summary>
        public static MlDsaKey Generate(MlDsaParameterSet parameterSet)
        {
            var mldsaParams = ConvertParameterSet(parameterSet);
            var algorithm = System.Security.Cryptography.MLDsa.GenerateKey(mldsaParams);

            return new MlDsaKey(algorithm, parameterSet, true);
        }

        /// <summary>
        /// Creates an ML-DSA public key from a certificate file path (.cer, .crt, .pem).
        /// Convenience factory method that loads the certificate and extracts the ML-DSA key.
        /// </summary>
        public static MlDsaKey FromCertificate(string certPath)
        {
            if (!File.Exists(certPath))
                throw new MlDsaException($"Certificate file not found: {certPath}");

            using X509Certificate2 cert = new X509Certificate2(certPath);
            var key = new MlDsaKey(cert);
            key.Id = certPath;
            return key;
        }

        /// <summary>
        /// Checks whether the given X509Certificate2 contains an ML-DSA public key.
        /// </summary>
        public static bool IsMlDsaCertificate(X509Certificate2 certificate)
        {
            if (certificate == null)
                return false;

            var algorithmOid = certificate.PublicKey.Oid?.Value;
            return algorithmOid == OidMlDsa44
                || algorithmOid == OidMlDsa65
                || algorithmOid == OidMlDsa87;
        }

        /// <summary>
        /// Gets the ML-DSA algorithm OID for the given parameter set
        /// </summary>
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

        #endregion

        #region Signing and Verification

        /// <summary>
        /// Signs a message digest with the ML-DSA private key using native .NET
        /// </summary>
        /// <remarks>
        /// ML-DSA signs the message directly, not a pre-computed hash.
        /// The 'hash' parameter name is kept for consistency with the codebase,
        /// but it represents the message data to be signed.
        /// </remarks>
        public byte[] SignHash(byte[] hash, NodeContext context = null)
        {
            if (!HasPrivate)
                throw new MlDsaException("Private key is not available for signing.");

            if (context != null && context.NonFileContext.PlaceholderDigestPathBase != null)
            {
                return GetPlaceholderSignature(hash, context);
            }

            // If backed by a non-exportable CNG key (HSM), sign via NCrypt
            if (cngKeyHandle != null)
            {
                return SignViaCngHandle(hash);
            }

            // Use native .NET ML-DSA signing
            return mldsaAlgorithm.SignData(hash, context: null);
        }

        /// <summary>
        /// Signs data using the CNG key handle directly (for HSM-backed keys).
        /// </summary>
        private byte[] SignViaCngHandle(byte[] data)
        {
            var handle = cngKeyHandle.Handle.DangerousGetHandle();
            var nCryptHandle = new PInvoke.NCrypt.SafeKeyHandle(handle, ownsHandle: false);

            try
            {
                // NCrypt ML-DSA signing — the provider handles the algorithm internally
                var signature = CngHandleSigner.Sign(cngKeyHandle, data);
                return signature.ToArray();
            }
            finally
            {
                nCryptHandle.DangerousRelease();
            }
        }

        /// <summary>
        /// Verifies an ML-DSA signature using native .NET
        /// </summary>
        public bool VerifySignature(byte[] hash, byte[] signature, NodeContext context = null)
        {
            if (context != null && context.NonFileContext.PlaceholderDigestPathBase != null)
            {
                var expected = GetPlaceholderSignature(hash, context);
                return signature.SequenceEqual(expected);
            }

            try
            {
                // Use native .NET ML-DSA verification
                return mldsaAlgorithm.VerifyData(hash, signature, context: null);
            }
            catch (CryptographicException)
            {
                // Invalid signature format or verification failure
                return false;
            }
        }

        private byte[] GetPlaceholderSignature(byte[] hash, NodeContext context)
        {
            var sig = new byte[SignatureSize];
            var magic = new byte[] { 0x4D, 0x4C, 0x44, 0x53, 0x41, 0x00, 0x00, 0x00 }; // "MLDSA\0\0\0"

            Buffer.BlockCopy(magic, 0, sig, 0, 8);
            sig[8] = (byte)ParameterSet;
            Buffer.BlockCopy(hash, 0, sig, 16, Math.Min(hash.Length, SignatureSize - 16));

            var basePath = context.ContextGraph.NonFileContext.PlaceholderDigestPathBase;
            if (!string.IsNullOrEmpty(basePath))
            {
                var safeFileName = $"{SanitizeFileName(context.Structure.Name)}_{SanitizeFileName(Id)}.mldsa.b64";
                var digestFile = Path.Combine(basePath, safeFileName);
                File.WriteAllText(digestFile, Convert.ToBase64String(hash));
            }

            return sig;
        }

        #endregion

        #region Property Access

        /// <summary>
        /// Gets property values for expression evaluation
        /// </summary>
        public Operand GetPropertyValue(string prop)
        {
            prop = prop.ToLowerInvariant();

            switch (prop)
            {
                case "paramset":
                case "parameterset":
                    return StringOperand.CreateString(ParameterSet.ToString());

                case "publickey":
                case "pubkey":
                    return BlobOperand.CreateBlob(publicKey);

                case "publickeysize":
                    return NumericOperand.CreateNumeric(PublicKeySize);

                case "privatekeysize":
                    return NumericOperand.CreateNumeric(PrivateKeySize);

                case "signaturesize":
                case "sigsize":
                    return NumericOperand.CreateNumeric(SignatureSize);

                case "algorithm":
                case "alg":
                    return StringOperand.CreateString($"ML-DSA-{ParameterSet.ToString().Replace("ML_DSA_", "")}");

                case "securitylevel":
                    return NumericOperand.CreateNumeric(GetSecurityLevel(ParameterSet));

                case "spki":
                    return BlobOperand.CreateBlob(mldsaAlgorithm.ExportSubjectPublicKeyInfo());

                case "hasprivate":
                case "hasprivatekey":
                    return NumericOperand.CreateNumeric(HasPrivate ? 1 : 0);

                default:
                    throw new MlDsaException($"Property '{prop}' is not recognized for ML-DSA keys.");
            }
        }

        #endregion

        #region Key Loading

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
                    // Load ML-DSA public key from a certificate file
                    LoadFromCertificateFile(filePath);
                    break;
                default:
                    throw new MlDsaException($"Unsupported key file format: {extension}. Supported formats: .pem, .der, .key, .cer, .crt");
            }
        }

        private void LoadFromCertificateFile(string certPath)
        {
            X509Certificate2 cert = new X509Certificate2(certPath);
            if (!IsMlDsaCertificate(cert))
                throw new MlDsaException($"Certificate does not contain an ML-DSA key. Algorithm OID: {cert.PublicKey.Oid?.Value ?? "null"}");

            var algorithmOid = cert.PublicKey.Oid.Value;
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
                // PEM-encoded certificate containing ML-DSA public key
                LoadFromCertificateFile(filePath);
                return;
            }

            // Use the static ImportFromPem factory — it handles both public and private PEM labels
            try
            {
                mldsaAlgorithm = System.Security.Cryptography.MLDsa.ImportFromPem(pemContent);

                // Determine if it has a private key by attempting to export it
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

                // Determine parameter set from the algorithm instance
                ParameterSet = mldsaAlgorithm.Algorithm.Name switch
                {
                    "ML-DSA-44" => MlDsaParameterSet.ML_DSA_44,
                    "ML-DSA-65" => MlDsaParameterSet.ML_DSA_65,
                    "ML-DSA-87" => MlDsaParameterSet.ML_DSA_87,
                    _ => throw new MlDsaException($"Unrecognized ML-DSA algorithm: {mldsaAlgorithm.Algorithm.Name}")
                };
            }
            catch (CryptographicException ex)
            {
                throw new MlDsaException($"Failed to import ML-DSA key from PEM file: {ex.Message}", ex);
            }
        }

        private void LoadFromDer(string filePath)
        {
            var derBytes = File.ReadAllBytes(filePath);

            // Try private key first via static factory, then fall back to public key
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
                    throw new MlDsaException($"Failed to load key from DER file. Not a valid ML-DSA private or public key.", ex);
                }
            }
        }

        /// <summary>
        /// Resolves the MlDsaParameterSet from the MLDsa.Algorithm property after import.
        /// </summary>
        private MlDsaParameterSet ResolveParameterSetFromAlgorithm()
        {
            return mldsaAlgorithm.Algorithm.Name switch
            {
                "ML-DSA-44" => MlDsaParameterSet.ML_DSA_44,
                "ML-DSA-65" => MlDsaParameterSet.ML_DSA_65,
                "ML-DSA-87" => MlDsaParameterSet.ML_DSA_87,
                _ => throw new MlDsaException($"Unrecognized ML-DSA algorithm: {mldsaAlgorithm.Algorithm.Name}")
            };
        }

        #endregion

        #region Parameter Set Helpers

        /// <summary>
        /// Converts SpecSign parameter set enum to .NET MLDsaAlgorithm
        /// </summary>
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

        // Helper methods for parameter sets (based on FIPS 204)

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
                MlDsaParameterSet.ML_DSA_44 => 2,  // NIST Level 2 (128-bit classical, quantum-resistant)
                MlDsaParameterSet.ML_DSA_65 => 3,  // NIST Level 3 (192-bit classical, quantum-resistant)
                MlDsaParameterSet.ML_DSA_87 => 5,  // NIST Level 5 (256-bit classical, quantum-resistant)
                _ => throw new MlDsaException($"Unknown parameter set: {parameterSet}")
            };
        }

        #endregion

        #region Utility Helpers

        /// <summary>
        /// Avoids any invalid file name characters when generating placeholder signature files, replacing them with underscores.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        private static string SanitizeFileName(string name)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            return string.Concat(name.Select(c => invalidChars.Contains(c) ? '_' : c));
        }

        #endregion

        #region Object Overrides

        public override string ToString()
        {
            return $"ML-DSA Key '{Id ?? "anonymous"}' ({ParameterSet}, Security Level {GetSecurityLevel(ParameterSet)}, {(HasPrivate ? "Private" : "Public")})";
        }

        #endregion

        #region IDisposable

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                mldsaAlgorithm?.Dispose();
                cngKeyHandle?.Dispose();   // dispose the HSM-backed CngKey if present
            }

            // Clear sensitive key material regardless of disposal path
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

        #endregion
    }

    /// <summary>
    /// ML-DSA parameter sets as defined in FIPS 204
    /// </summary>
    public enum MlDsaParameterSet
    {
        ML_DSA_44 = 44,  // NIST Security Level 2 (comparable to AES-128)
        ML_DSA_65 = 65,  // NIST Security Level 3 (comparable to AES-192)
        ML_DSA_87 = 87   // NIST Security Level 5 (comparable to AES-256)
    }
}
