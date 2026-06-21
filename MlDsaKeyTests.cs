using CommandLine;
using Ess.Sign.SignTools.SpecSign.Crypto;
using Ess.Sign.SignTools.SpecSign.Crypto.MLDsa;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;

#pragma warning disable SYSLIB5006 // ML-DSA is experimental in .NET 10 preview

namespace Ess.Sign.SignTools.SpecSign.Tests.Crypto
{
    public class MlDsaKeyTests
    {
        #region Key Generation

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void Generate_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);

            Assert.True(key.HasPrivate);
            Assert.Equal(parameterSet, key.ParameterSet);
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44, 1312, 2560, 2420)]
        [InlineData(MlDsaParameterSet.ML_DSA_65, 1952, 4032, 3309)]
        [InlineData(MlDsaParameterSet.ML_DSA_87, 2592, 4896, 4627)]
        public void KeySizes_MatchFips204_MlDsaKeyTest(MlDsaParameterSet parameterSet, int expectedPub, int expectedPriv, int expectedSig)
        {
            using var key = MlDsaKey.Generate(parameterSet);

            Assert.Equal(expectedPub, key.PublicKeySize);
            Assert.Equal(expectedPriv, key.PrivateKeySize);
            Assert.Equal(expectedSig, key.SignatureSize);
        }

        #endregion

        #region Sign and Verify

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void SignAndVerify_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);

            for (int i = 0; i < 3; i++)
            {
                var data = new byte[32 + i * 32];
                Random.Shared.NextBytes(data);

                var signature = key.SignHash(data);

                Assert.Equal(key.SignatureSize, signature.Length);
                Assert.True(key.VerifySignature(data, signature));
            }
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void SignAndVerifyEmpty_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);
            var data = Array.Empty<byte>();

            var signature = key.SignHash(data);

            Assert.True(key.VerifySignature(data, signature));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void VerifyFailsTamperedData_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);
            var data = new byte[64];
            Random.Shared.NextBytes(data);

            var signature = key.SignHash(data);
            data[0] ^= 0xFF;

            Assert.False(key.VerifySignature(data, signature));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void VerifyFailsTamperedSignature_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);
            var data = new byte[64];
            Random.Shared.NextBytes(data);

            var signature = key.SignHash(data);
            signature[signature.Length / 2] ^= 0xFF;

            Assert.False(key.VerifySignature(data, signature));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void VerifyFailsWrongKey_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key1 = MlDsaKey.Generate(parameterSet);
            using var key2 = MlDsaKey.Generate(parameterSet);
            var data = new byte[64];
            Random.Shared.NextBytes(data);

            var signature = key1.SignHash(data);

            Assert.False(key2.VerifySignature(data, signature));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void NonDeterministicSignatures_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);
            var data = new byte[64];
            Random.Shared.NextBytes(data);

            var sig1 = key.SignHash(data);
            var sig2 = key.SignHash(data);

            Assert.True(key.VerifySignature(data, sig1));
            Assert.True(key.VerifySignature(data, sig2));
            Assert.False(sig1.SequenceEqual(sig2));
        }

        [Fact]
        public void CrossParameterSetVerifyFails_MlDsaKeyTest()
        {
            using var key44 = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_44);
            using var key65 = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_65);
            var data = new byte[64];
            Random.Shared.NextBytes(data);

            var sig = key44.SignHash(data);

            Assert.False(key65.VerifySignature(data, sig));
        }

        #endregion

        #region Public Key Only

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void PublicKeyOnlyVerifies_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var privateKey = MlDsaKey.Generate(parameterSet);
            var data = new byte[64];
            Random.Shared.NextBytes(data);
            var signature = privateKey.SignHash(data);

            var spkiBytes = privateKey.GetPropertyValue("spki").GetBlob();
            using var publicKey = new MlDsaKey(spkiBytes, parameterSet, isPrivate: false);

            Assert.False(publicKey.HasPrivate);
            Assert.True(publicKey.VerifySignature(data, signature));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void PublicKeyOnlySignThrows_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var privateKey = MlDsaKey.Generate(parameterSet);
            var spkiBytes = privateKey.GetPropertyValue("spki").GetBlob();
            using var publicKey = new MlDsaKey(spkiBytes, parameterSet, isPrivate: false);

            Assert.ThrowsAny<MlDsaException>(() => publicKey.SignHash(new byte[32]));
        }

        #endregion

        #region Certificate-Based Tests

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void CreateFromCertificate_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var nativeKey = MlDsaTestHelper.GetOrCreateMlDsaKey($"cert-test-{parameterSet}", parameterSet);
            var cert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(nativeKey, $"CN=MlDsa-{parameterSet}");

            // Get public-only cert (strip private key)
            var pubCert = MlDsaTestHelper.GetPublicOnlyCert(cert);

            using var mlDsaKey = new MlDsaKey(pubCert);

            Assert.False(mlDsaKey.HasPrivate);
            Assert.Equal(parameterSet, mlDsaKey.ParameterSet);
            Assert.True(MlDsaKey.IsMlDsaCertificate(pubCert));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void CertKeyVerifiesNativeSignature_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            // Generate native key, sign data, create cert, verify via MlDsaKey wrapper
            var nativeKey = MlDsaTestHelper.GetOrCreateMlDsaKey($"cert-verify-{parameterSet}", parameterSet);
            var data = new byte[100];
            Random.Shared.NextBytes(data);
            var signature = nativeKey.SignData(data, context: null);

            var cert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(nativeKey, $"CN=MlDsa-Verify-{parameterSet}");
            var pubCert = MlDsaTestHelper.GetPublicOnlyCert(cert);

            using var mlDsaKey = new MlDsaKey(pubCert);

            Assert.True(mlDsaKey.VerifySignature(data, signature));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void CertKeyTamperedDataFails_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var nativeKey = MlDsaTestHelper.GetOrCreateMlDsaKey($"cert-tamper-{parameterSet}", parameterSet);
            var data = new byte[100];
            Random.Shared.NextBytes(data);
            var signature = nativeKey.SignData(data, context: null);

            var cert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(nativeKey, $"CN=MlDsa-Tamper-{parameterSet}");
            var pubCert = MlDsaTestHelper.GetPublicOnlyCert(cert);

            using var mlDsaKey = new MlDsaKey(pubCert);

            data[0] ^= 0xFF;
            Assert.False(mlDsaKey.VerifySignature(data, signature));
        }

        [Fact]
        public void IsMlDsaCertificateNullReturnsFalse_MlDsaKeyTest()
        {
            Assert.False(MlDsaKey.IsMlDsaCertificate(null));
        }

        [Fact]
        public void IsMlDsaCertificateNonMlDsaReturnsFalse_MlDsaKeyTest()
        {
            // Create an RSA certificate — should not be recognized as ML-DSA
            using var rsa = RSA.Create(2048);
            var csr = new CertificateRequest("CN=RSA Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var rsaCert = csr.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

            Assert.False(MlDsaKey.IsMlDsaCertificate(rsaCert));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void IsMlDsaCertificateReturnsTrue_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var nativeKey = MlDsaTestHelper.GetOrCreateMlDsaKey($"cert-ischeck-{parameterSet}", parameterSet);
            var cert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(nativeKey, $"CN=MlDsa-IsCheck-{parameterSet}");

            Assert.True(MlDsaKey.IsMlDsaCertificate(cert));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void FromCertificateFile_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var nativeKey = MlDsaTestHelper.GetOrCreateMlDsaKey($"cert-file-{parameterSet}", parameterSet);
            var cert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(nativeKey, $"CN=MlDsa-File-{parameterSet}");

            // Write cert to temp file
            var tempPath = Path.GetTempFileName() + ".cer";
            try
            {
                File.WriteAllBytes(tempPath, cert.RawData);

                using var mlDsaKey = MlDsaKey.FromCertificate(tempPath);

                Assert.False(mlDsaKey.HasPrivate);
                Assert.Equal(parameterSet, mlDsaKey.ParameterSet);
                Assert.Equal(tempPath, mlDsaKey.Id);
            }
            finally
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void CertSignedByIssuer_VerifiesWithLeafCert_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            // Create issuer (CA) key and self-signed cert
            var issuerAlg = MlDsaTestHelper.ConvertParameterSet(parameterSet);
            using var issuerKey = MLDsa.GenerateKey(issuerAlg);
            var issuerCert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(issuerKey, "CN=ML-DSA Test CA");

            // Create leaf key and cert signed by issuer
            using var leafKey = MLDsa.GenerateKey(issuerAlg);
            var leafCert = MlDsaTestHelper.CreateMlDsaCertSignedByIssuer(
                leafKey, issuerKey, issuerCert.SubjectName,
                $"CN=ML-DSA Leaf {parameterSet}");

            // Sign data with the leaf's native key
            var data = new byte[128];
            Random.Shared.NextBytes(data);
            var signature = leafKey.SignData(data, context: null);

            // Import from the public-only leaf cert into MlDsaKey and verify
            var pubLeafCert = MlDsaTestHelper.GetPublicOnlyCert(leafCert);
            using var mlDsaKey = new MlDsaKey(pubLeafCert);

            Assert.False(mlDsaKey.HasPrivate);
            Assert.Equal(parameterSet, mlDsaKey.ParameterSet);
            Assert.True(mlDsaKey.VerifySignature(data, signature));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void CertSpkiMatchesGeneratedKey_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var nativeKey = MlDsaTestHelper.GetOrCreateMlDsaKey($"cert-spki-{parameterSet}", parameterSet);
            var cert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(nativeKey, $"CN=MlDsa-Spki-{parameterSet}");

            var pubCert = MlDsaTestHelper.GetPublicOnlyCert(cert);
            using var mlDsaKey = new MlDsaKey(pubCert);

            // SPKI from MlDsaKey should match SPKI exported from the native key
            var keySpki = mlDsaKey.GetPropertyValue("spki").GetBlob();
            var nativeSpki = nativeKey.ExportSubjectPublicKeyInfo();

            Assert.True(keySpki.SequenceEqual(nativeSpki));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void CertPemFile_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var nativeKey = MlDsaTestHelper.GetOrCreateMlDsaKey($"cert-pem-{parameterSet}", parameterSet);
            var cert = MlDsaTestHelper.CreateSelfSignedMlDsaCert(nativeKey, $"CN=MlDsa-Pem-{parameterSet}");

            // Write cert as PEM to temp file
            var tempPath = Path.GetTempFileName() + ".pem";
            try
            {
                var pem = cert.ExportCertificatePem();
                File.WriteAllText(tempPath, pem);

                // The file-path constructor should detect BEGIN CERTIFICATE and load via cert path
                using var mlDsaKey = new MlDsaKey(tempPath);

                Assert.False(mlDsaKey.HasPrivate);
                Assert.Equal(parameterSet, mlDsaKey.ParameterSet);

                // Verify a signature produced by the native key
                var data = new byte[64];
                Random.Shared.NextBytes(data);
                var signature = nativeKey.SignData(data, context: null);

                Assert.True(mlDsaKey.VerifySignature(data, signature));
            }
            finally
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
        }

        #endregion

        #region PKCS#8 / SPKI Round Trip

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void SpkiRoundTrip_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var original = MlDsaKey.Generate(parameterSet);
            var spki = original.GetPropertyValue("spki").GetBlob();

            using var reimported = MLDsa.ImportSubjectPublicKeyInfo(spki);
            var reimportedSpki = reimported.ExportSubjectPublicKeyInfo();

            Assert.True(spki.SequenceEqual(reimportedSpki));
        }

        #endregion

        #region Native .NET Interop

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void SignWithWrapper_VerifyWithNative_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);
            var data = new byte[100];
            Random.Shared.NextBytes(data);

            var signature = key.SignHash(data);

            var spkiBytes = key.GetPropertyValue("spki").GetBlob();
            using var nativeKey = MLDsa.ImportSubjectPublicKeyInfo(spkiBytes);

            Assert.True(nativeKey.VerifyData(data, signature, context: null));
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void SignWithNative_VerifyWithWrapper_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var mldsaAlg = MlDsaTestHelper.ConvertParameterSet(parameterSet);
            using var nativeKey = MLDsa.GenerateKey(mldsaAlg);

            var data = new byte[100];
            Random.Shared.NextBytes(data);
            var signature = nativeKey.SignData(data, context: null);

            var spkiBytes = nativeKey.ExportSubjectPublicKeyInfo();
            using var wrapperKey = new MlDsaKey(spkiBytes, parameterSet, isPrivate: false);

            Assert.True(wrapperKey.VerifySignature(data, signature));
        }

        #endregion
      
        #region GetPropertyValue

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44, "ML-DSA-44")]
        [InlineData(MlDsaParameterSet.ML_DSA_65, "ML-DSA-65")]
        [InlineData(MlDsaParameterSet.ML_DSA_87, "ML-DSA-87")]
        public void GetPropertyAlgorithm_MlDsaKeyTest(MlDsaParameterSet parameterSet, string expectedAlg)
        {
            using var key = MlDsaKey.Generate(parameterSet);

            Assert.Equal(expectedAlg, key.GetPropertyValue("alg").GetString());
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44, 2)]
        [InlineData(MlDsaParameterSet.ML_DSA_65, 3)]
        [InlineData(MlDsaParameterSet.ML_DSA_87, 5)]
        public void GetPropertySecurityLevel_MlDsaKeyTest(MlDsaParameterSet parameterSet, int expectedLevel)
        {
            using var key = MlDsaKey.Generate(parameterSet);

            Assert.Equal(expectedLevel, (int)key.GetPropertyValue("securitylevel").GetNumeric());
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void GetPropertyHasPrivate_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);

            Assert.Equal(1, (int)key.GetPropertyValue("hasprivate").GetNumeric());
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void GetPropertySigSize_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);

            Assert.Equal(key.SignatureSize, (int)key.GetPropertyValue("sigsize").GetNumeric());
        }

        [Theory]
        [InlineData("unknownprop")]
        [InlineData("invalidproperty")]
        public void GetPropertyUnknownThrows_MlDsaKeyTest(string prop)
        {
            using var key = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_44);

            Assert.ThrowsAny<Exception>(() => key.GetPropertyValue(prop));
        }

        #endregion

        #region GetAlgorithmOid

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44, "2.16.840.1.101.3.4.3.17")]
        [InlineData(MlDsaParameterSet.ML_DSA_65, "2.16.840.1.101.3.4.3.18")]
        [InlineData(MlDsaParameterSet.ML_DSA_87, "2.16.840.1.101.3.4.3.19")]
        public void GetAlgorithmOid_MlDsaKeyTest(MlDsaParameterSet parameterSet, string expectedOid)
        {
            Assert.Equal(expectedOid, MlDsaKey.GetAlgorithmOid(parameterSet));
        }

        #endregion

        #region ToString

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void ToStringContainsParameterSet_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var key = MlDsaKey.Generate(parameterSet);
            var str = key.ToString();

            Assert.Contains(parameterSet.ToString(), str);
            Assert.Contains("Private", str);
        }

        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void ToStringPublicKeyOnly_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            using var privateKey = MlDsaKey.Generate(parameterSet);
            var spkiBytes = privateKey.GetPropertyValue("spki").GetBlob();
            using var publicKey = new MlDsaKey(spkiBytes, parameterSet, isPrivate: false);

            var str = publicKey.ToString();

            Assert.Contains("Public", str);
            Assert.DoesNotContain("Private", str);
        }

        #endregion

        #region Certificate Loading (p7b chain)

        private const string P7bCertPath = @"Crypto\mldsacerts\MLDSA-L2-TSS-SW-Test-CodeSigning.p7b";

        private static X509Certificate2Collection LoadP7bCerts()
        {
            var certs = new X509Certificate2Collection();
            certs.Import(P7bCertPath);
            return certs;
        }

        [Fact]
        public void LoadP7b_ContainsThreeCerts_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            Assert.Equal(3, certs.Count);
        }

        [Fact]
        public void LoadP7b_AllAreMlDsaCertificates_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            foreach (var cert in certs)
            {
                Assert.True(MlDsaKey.IsMlDsaCertificate(cert),
                    $"Certificate '{cert.Subject}' should be identified as ML-DSA.");
            }
        }

        [Fact]
        public void LoadP7b_LeafCertIsMlDsa44_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            var leaf = certs.Cast<X509Certificate2>().First(c => c.Subject.Contains("CodeSigning"));

            using var key = new MlDsaKey(leaf);

            Assert.Equal(MlDsaParameterSet.ML_DSA_44, key.ParameterSet);
            Assert.False(key.HasPrivate);
            Assert.Equal(1312, key.PublicKeySize);
            Assert.Equal(2420, key.SignatureSize);
        }

        [Fact]
        public void LoadP7b_IcaCertIsMlDsa65_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            var ica = certs.Cast<X509Certificate2>().First(c => c.Subject.Contains("ICA"));

            using var key = new MlDsaKey(ica);

            Assert.Equal(MlDsaParameterSet.ML_DSA_65, key.ParameterSet);
            Assert.False(key.HasPrivate);
            Assert.Equal(1952, key.PublicKeySize);
            Assert.Equal(3309, key.SignatureSize);
        }

        [Fact]
        public void LoadP7b_RootCertIsMlDsa87_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            var root = certs.Cast<X509Certificate2>().First(c => c.Subject.Contains("Root-CA"));

            using var key = new MlDsaKey(root);

            Assert.Equal(MlDsaParameterSet.ML_DSA_87, key.ParameterSet);
            Assert.False(key.HasPrivate);
            Assert.Equal(2592, key.PublicKeySize);
            Assert.Equal(4627, key.SignatureSize);
        }

        [Fact]
        public void LoadP7b_PublicOnlyKey_CannotSign_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            var leaf = certs.Cast<X509Certificate2>().First(c => c.Subject.Contains("CodeSigning"));

            using var key = new MlDsaKey(leaf);

            Assert.False(key.HasPrivate);
            Assert.Throws<MlDsaException>(() => key.SignHash(new byte[32]));
        }

        [Fact]
        public void LoadP7b_PublicOnlyKey_CanVerify_MlDsaKeyTest()
        {
            // Sign with a generated key of the same parameter set, verify with cert's public key
            var certs = LoadP7bCerts();
            var leaf = certs.Cast<X509Certificate2>().First(c => c.Subject.Contains("CodeSigning"));
            using var certKey = new MlDsaKey(leaf);

            // Generate a matching key to produce a signature
            using var signingKey = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_44);
            var data = new byte[64];
            Random.Shared.NextBytes(data);
            var signature = signingKey.SignHash(data);

            // The cert key can't verify a signature from a different key — verifies VerifySignature doesn't throw
            Assert.False(certKey.VerifySignature(data, signature));
        }

        [Fact]
        public void LoadP7b_IdIsSetToSubject_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            var leaf = certs.Cast<X509Certificate2>().First(c => c.Subject.Contains("CodeSigning"));

            using var key = new MlDsaKey(leaf);

            Assert.Contains("MLDSA-L2-TSS-SW-Test-CodeSigning", key.Id);
        }

        [Fact]
        public void LoadP7b_WrapInKeyClass_IsMlDsaTrue_MlDsaKeyTest()
        {
            var certs = LoadP7bCerts();
            var leaf = certs.Cast<X509Certificate2>().First(c => c.Subject.Contains("CodeSigning"));

            using var mlDsaKey = new MlDsaKey(leaf);
            var key = new Key(mlDsaKey);

            Assert.True(key.IsMlDsa);
            Assert.False(key.IsEcc);
            Assert.False(key.IsRsa);
            Assert.False(key.HasPrivate);
        }

        #endregion

        #region Full Flow - Key(container, provider) with ML-DSA

        /// <summary>
        /// Full flow: Load ML-DSA public key from .p7b file via Key(container, provider:null).
        /// This exercises GetCngKeyFromFile → GetFromCert → MlDsaKey(X509Certificate2).
        /// </summary>
        [Fact]
        public void FullFlow_KeyFromP7bFile_MlDsa44_PublicOnly_MlDsaKeyTest()
        {
            var key = new Key(P7bCertPath, provider: null);

            Assert.True(key.IsMlDsa);
            Assert.False(key.IsEcc);
            Assert.False(key.IsRsa);
            Assert.False(key.HasPrivate);
            Assert.Equal(P7bCertPath, key.Id);
            Assert.Equal(2420 * 8, key.SigSize);
            Assert.Equal(2420, key.SigSizeBytes);
        }

        /// <summary>
        /// Full flow: Generate ML-DSA-44 key, persist to CNG, open via CngKey, wrap in Key class,
        /// then sign and verify through the full Key.SignHash / Key.VerifySignature path.
        /// </summary>
        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void FullFlow_CngRoundtrip_SignAndVerify_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            // 1. Generate ML-DSA key and get PKCS8 via .NET crypto
            var mlDsaParams = parameterSet switch
            {
                MlDsaParameterSet.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
                MlDsaParameterSet.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
                MlDsaParameterSet.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
                _ => throw new ArgumentOutOfRangeException()
            };
            using var mlDsa = MLDsa.GenerateKey(mlDsaParams);
            var pkcs8 = mlDsa.ExportPkcs8PrivateKey();

            // 2. Import into CNG (simulates KSP-stored key)
            CngKey cngKey;
            byte[] cngExportedPkcs8;
            try
            {
                cngKey = CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob);
                // 3. Re-export from CNG (exactly what CreateMlDsaKeyFromCngKey does)
                cngExportedPkcs8 = cngKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
            }
            catch (CryptographicException)
            {
                // CNG ML-DSA import/export not fully supported on this OS (requires Windows 11 24H2+)
                return;
            }

            // 4. Construct MlDsaKey from CNG-exported bytes
            using var cngMlDsaKey = new MlDsaKey(cngExportedPkcs8, parameterSet, isPrivate: true);
            var key = new Key(cngMlDsaKey);

            Assert.True(key.IsMlDsa);
            Assert.True(key.HasPrivate);

            // 5. Sign through the Key class
            var data = new byte[64];
            Random.Shared.NextBytes(data);
            var signature = key.SignHash(data, isPssPadding: false);

            Assert.Equal(cngMlDsaKey.SignatureSize, signature.Length);

            // 6. Verify through the Key class
            Assert.True(key.VerifySignature(data, signature, isPssPadding: false));

            // 7. Tampered data fails
            data[0] ^= 0xFF;
            Assert.False(key.VerifySignature(data, signature, isPssPadding: false));

            cngKey.Dispose();
            CryptographicOperations.ZeroMemory(pkcs8);
            CryptographicOperations.ZeroMemory(cngExportedPkcs8);
        }

        /// <summary>
        /// Full flow: Import CNG key from PKCS8, validate algorithm group is not ECDsa/RSA,
        /// re-export and verify key sizes match expected values.
        /// </summary>
        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44, 1312, 2420)]
        [InlineData(MlDsaParameterSet.ML_DSA_65, 1952, 3309)]
        [InlineData(MlDsaParameterSet.ML_DSA_87, 2592, 4627)]
        public void FullFlow_CngKeyImport_ValidateAlgorithmGroup_MlDsaKeyTest(
            MlDsaParameterSet parameterSet, int expectedPubSize, int expectedSigSize)
        {
            // Generate key using native .NET
            var mlDsaParams = parameterSet switch
            {
                MlDsaParameterSet.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
                MlDsaParameterSet.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
                MlDsaParameterSet.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
                _ => throw new ArgumentOutOfRangeException()
            };
            using var mlDsa = MLDsa.GenerateKey(mlDsaParams);
            var pkcs8 = mlDsa.ExportPkcs8PrivateKey();

            // Import into CNG (ephemeral) — simulates what KSP returns
            CngKey cngKey;
            byte[] reExportedPkcs8;
            try
            {
                cngKey = CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob);
                // Re-export from CNG and create MlDsaKey (same as CreateMlDsaKeyFromCngKey)
                reExportedPkcs8 = cngKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
            }
            catch (CryptographicException)
            {
                // CNG ML-DSA import/export not fully supported on this OS (requires Windows 11 24H2+)
                return;
            }

            // ML-DSA keys should NOT be ECDsa or RSA groups
            Assert.NotEqual(CngAlgorithmGroup.ECDsa, cngKey.AlgorithmGroup);
            Assert.NotEqual(CngAlgorithmGroup.Rsa, cngKey.AlgorithmGroup);

            using var mlDsaKey = new MlDsaKey(reExportedPkcs8, parameterSet, isPrivate: true);

            Assert.True(mlDsaKey.HasPrivate);
            Assert.Equal(parameterSet, mlDsaKey.ParameterSet);
            Assert.Equal(expectedPubSize, mlDsaKey.PublicKeySize);
            Assert.Equal(expectedSigSize, mlDsaKey.SignatureSize);

            // Sign with the CNG-round-tripped key, verify with original key
            var data = new byte[32];
            Random.Shared.NextBytes(data);
            var signature = mlDsaKey.SignHash(data);

            // Verify via native MLDsa
            Assert.True(mlDsa.VerifyData(data, signature, ReadOnlySpan<byte>.Empty));

            cngKey.Dispose();
            CryptographicOperations.ZeroMemory(pkcs8);
            CryptographicOperations.ZeroMemory(reExportedPkcs8);
        }

        /// <summary>
        /// Full flow: p7b cert loaded via Key(container, null) — sign with generated key,
        /// verify with cert public key via Key class VerifySignature.
        /// </summary>
        [Fact]
        public void FullFlow_P7bPublicKey_VerifySignatureFromGeneratedKey_MlDsaKeyTest()
        {
            // Load the leaf cert (ML-DSA-44) through Key(file, null) path
            var pubKey = new Key(P7bCertPath, provider: null);
            Assert.True(pubKey.IsMlDsa);
            Assert.False(pubKey.HasPrivate);

            // Generate a separate ML-DSA-44 key for signing
            using var signingMlDsa = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_44);
            var signingKey = new Key(signingMlDsa);

            var data = new byte[64];
            Random.Shared.NextBytes(data);
            var signature = signingKey.SignHash(data, isPssPadding: false);

            // Cert key can't verify a different key's signature (proves verify doesn't throw)
            Assert.False(pubKey.VerifySignature(data, signature, isPssPadding: false));
        }

        /// <summary>
        /// Full flow: Verify Key.ToString() returns "ML-DSA Key" when loaded from p7b.
        /// </summary>
        [Fact]
        public void FullFlow_KeyFromP7b_ToString_MlDsaKeyTest()
        {
            var key = new Key(P7bCertPath, provider: null);
            var str = key.ToString();
            Assert.Contains("ML-DSA", str);
            Assert.DoesNotContain("RSA", str);
            Assert.DoesNotContain("ECC", str);
        }

        /// <summary>
        /// Full flow: p7b cert loaded via Key(container, null) — verify it cannot sign (public-only).
        /// </summary>
        [Fact]
        public void FullFlow_P7bPublicKey_CannotSign_MlDsaKeyTest()
        {
            var pubKey = new Key(P7bCertPath, provider: null);

            Assert.True(pubKey.IsMlDsa);
            Assert.False(pubKey.HasPrivate);
            Assert.Throws<BlueshiftKeyException>(() => pubKey.SignHash(new byte[32], isPssPadding: false));
        }

        /// <summary>
        /// Full flow: Persist ML-DSA key in CNG named container, open by name, export PKCS8,
        /// create MlDsaKey, and sign/verify — tests the actual Key Storage Provider path.
        /// </summary>
        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void FullFlow_PersistedCngContainer_SignVerify_MlDsaKeyTest(MlDsaParameterSet parameterSet)
        {
            var containerName = $"CopilotTest_MLDSA_{parameterSet}_{Guid.NewGuid():N}";
            CngKey persistedKey = null;
            try
            {
                // 1. Generate and export PKCS8
                var mlDsaParams = parameterSet switch
                {
                    MlDsaParameterSet.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
                    MlDsaParameterSet.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
                    MlDsaParameterSet.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
                    _ => throw new ArgumentOutOfRangeException()
                };
                using var mlDsa = MLDsa.GenerateKey(mlDsaParams);
                var pkcs8 = mlDsa.ExportPkcs8PrivateKey();

                // 2. Try to create a persisted CNG key with this algorithm
                var algorithm = new CngAlgorithm(parameterSet switch
                {
                    MlDsaParameterSet.ML_DSA_44 => "ML-DSA-44",
                    MlDsaParameterSet.ML_DSA_65 => "ML-DSA-65",
                    MlDsaParameterSet.ML_DSA_87 => "ML-DSA-87",
                    _ => throw new ArgumentOutOfRangeException()
                });
                var creationParams = new CngKeyCreationParameters
                {
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport | CngExportPolicies.AllowExport,
                    KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider
                };

                try
                {
                    persistedKey = CngKey.Create(algorithm, containerName, creationParams);
                }
                catch (CryptographicException)
                {
                    // Platform may not support persisted ML-DSA CNG key creation — skip
                    return;
                }

                // 3. Open the persisted key by container name
                var openedKey = CngKey.Open(containerName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
                var openedPkcs8 = openedKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);

                // 4. Create MlDsaKey from the container-opened key
                // Determine parameter set from the exported key
                using var importedMlDsa = MLDsa.ImportPkcs8PrivateKey(openedPkcs8);
                var detectedSet = importedMlDsa.Algorithm.Name switch
                {
                    "ML-DSA-44" => MlDsaParameterSet.ML_DSA_44,
                    "ML-DSA-65" => MlDsaParameterSet.ML_DSA_65,
                    "ML-DSA-87" => MlDsaParameterSet.ML_DSA_87,
                    _ => throw new Exception($"Unexpected: {importedMlDsa.Algorithm.Name}")
                };
                Assert.Equal(parameterSet, detectedSet);

                using var containerMlDsa = new MlDsaKey(openedPkcs8, parameterSet, isPrivate: true);
                var key = new Key(containerMlDsa);

                // 5. Sign and verify through Key class
                var data = new byte[48];
                Random.Shared.NextBytes(data);
                var signature = key.SignHash(data, isPssPadding: false);

                Assert.True(key.VerifySignature(data, signature, isPssPadding: false));

                openedKey.Dispose();
                importedMlDsa.Dispose();
                CryptographicOperations.ZeroMemory(pkcs8);
                CryptographicOperations.ZeroMemory(openedPkcs8);
            }
            finally
            {
                try { persistedKey?.Delete(); } catch { }
                try { CngKey.Open(containerName, CngProvider.MicrosoftSoftwareKeyStorageProvider).Delete(); } catch { }
            }
        }

        #endregion

        #region Dispose

        [Fact]
        public void Dispose_MlDsaKeyTest()
        {
            var key = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_44);
            key.Dispose();

            var ex = Record.Exception(() => key.Dispose());
            Assert.Null(ex);
        }

        #endregion
    }
}