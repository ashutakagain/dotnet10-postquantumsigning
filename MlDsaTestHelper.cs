using Ess.Sign.SignTools.SpecSign.Crypto.MLDsa;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10 preview

namespace Ess.Sign.SignTools.SpecSign.Tests.Crypto
{
    public static class MlDsaTestHelper
    {
        private static ConcurrentDictionary<string, MLDsa> keyCache => lazyKeyCache.Value;
        private static Lazy<ConcurrentDictionary<string, MLDsa>> lazyKeyCache = new Lazy<ConcurrentDictionary<string, MLDsa>>(() =>
        {
            return new ConcurrentDictionary<string, MLDsa>();
        });

        private static ConcurrentDictionary<string, X509Certificate2> certCache => lazyCertCache.Value;
        private static Lazy<ConcurrentDictionary<string, X509Certificate2>> lazyCertCache = new Lazy<ConcurrentDictionary<string, X509Certificate2>>(() =>
        {
            return new ConcurrentDictionary<string, X509Certificate2>();
        });

        private static Random rnd = new Random();

        /// <summary>
        /// Converts MlDsaParameterSet to the native MLDsaAlgorithm.
        /// </summary>
        public static MLDsaAlgorithm ConvertParameterSet(MlDsaParameterSet parameterSet)
        {
            return parameterSet switch
            {
                MlDsaParameterSet.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
                MlDsaParameterSet.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
                MlDsaParameterSet.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
                _ => throw new ArgumentException($"Unknown parameter set: {parameterSet}")
            };
        }

        /// <summary>
        /// Gets or creates a cached ML-DSA key for a given name and parameter set.
        /// Keys are cached to avoid regeneration overhead across tests.
        /// </summary>
        public static MLDsa GetOrCreateMlDsaKey(string name, MlDsaParameterSet parameterSet)
        {
            if (!keyCache.ContainsKey(name) && keyCache.TryAdd(name, null))
            {
                var alg = ConvertParameterSet(parameterSet);
                keyCache[name] = MLDsa.GenerateKey(alg);
            }

            int i = 0;
            while (i < 10 && keyCache[name] == null)
            {
                Thread.Sleep(10);
                i++;
            }

            if (i >= 10)
                throw new Exception($"Failed to get ML-DSA key '{name}'.");

            return keyCache[name];
        }

        /// <summary>
        /// Creates a self-signed X509Certificate2 with an ML-DSA key pair.
        /// The returned certificate has the private key attached.
        /// </summary>
        public static X509Certificate2 CreateSelfSignedMlDsaCert(
            MLDsa mldsaKey,
            string subject = "CN=ML-DSA Test",
            int validDays = 5)
        {
            // .NET 10 CertificateRequest supports MLDsa directly
            var csr = new CertificateRequest(subject, mldsaKey);

            csr.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            csr.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(csr.PublicKey, false));
            csr.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

            var cert = csr.CreateSelfSigned(
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddDays(validDays));

            return cert;
        }

        /// <summary>
        /// Creates an ML-DSA leaf certificate signed by an issuer ML-DSA key.
        /// Returns the leaf certificate with the leaf's private key attached.
        /// </summary>
        public static X509Certificate2 CreateMlDsaCertSignedByIssuer(
            MLDsa leafKey,
            MLDsa issuerKey,
            X500DistinguishedName issuerSubject,
            string leafSubject = "CN=ML-DSA Leaf",
            int validDays = 5)
        {
            var csr = new CertificateRequest(leafSubject, leafKey);

            csr.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            csr.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(csr.PublicKey, false));
            csr.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

            var sn = new byte[32];
            rnd.NextBytes(sn);

            // Create the signature generator from the issuer's ML-DSA key
            var issuerGen = X509SignatureGenerator.CreateForMLDsa(issuerKey);

            var cert = csr.Create(
                issuerSubject,
                issuerGen,
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddDays(validDays),
                sn);

            // Attach the leaf's private key to the certificate
            return cert.CopyWithPrivateKey(leafKey);
        }

        /// <summary>
        /// Gets or creates a cached self-signed ML-DSA certificate for a given name and parameter set.
        /// </summary>
        public static X509Certificate2 GetOrCreateSelfSignedMlDsaCert(string name, MlDsaParameterSet parameterSet)
        {
            if (!certCache.ContainsKey(name) && certCache.TryAdd(name, null))
            {
                var mldsaKey = GetOrCreateMlDsaKey(name, parameterSet);
                certCache[name] = CreateSelfSignedMlDsaCert(mldsaKey, $"CN={name}");
            }

            int i = 0;
            while (i < 10 && certCache[name] == null)
            {
                Thread.Sleep(10);
                i++;
            }

            if (i >= 10)
                throw new Exception($"Failed to get ML-DSA cert '{name}'.");

            return certCache[name];
        }

        /// <summary>
        /// Returns the public-key-only X509Certificate2 (private key stripped).
        /// Useful for testing the MlDsaKey(X509Certificate2) constructor path.
        /// </summary>
        public static X509Certificate2 GetPublicOnlyCert(X509Certificate2 certWithPrivateKey)
        {
            // Re-import from raw data — this strips the private key
            return new X509Certificate2(certWithPrivateKey.RawData);
        }
    }
}