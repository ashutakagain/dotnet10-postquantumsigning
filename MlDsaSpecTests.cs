using Ess.Sign.SignTools.SpecSign.Context;
using Ess.Sign.SignTools.SpecSign.Crypto;
using Ess.Sign.SignTools.SpecSign.Crypto.MLDsa;
using Ess.Sign.SignTools.SpecSign.Tests.Crypto;
using Ess.Sign.SignTools.SpecSign.Yaml;
using System;
using System.IO;
using System.Security.Cryptography;
using Xunit;

namespace Ess.Sign.SignTools.SpecSign.Tests.Mldsa
{
    public class MlDsaSpecTests
    {
        private const string SpecPath = @"E2E\Raw\raw-content-sign.yaml";

        /// <summary>
        /// E2E test: Signs a binary payload using the raw-content-sign spec with ML-DSA,
        /// then verifies the output structure: suppressed content + signature.
        /// </summary>
        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44, 2420)]
        [InlineData(MlDsaParameterSet.ML_DSA_65, 3309)]
        [InlineData(MlDsaParameterSet.ML_DSA_87, 4627)]
        public void E2E_MlDsa_SignAndVerifyTest(MlDsaParameterSet parameterSet, int expectedSigSize)
        {
            // Arrange: generate an ephemeral ML-DSA key
            var mlDsaKey = MlDsaKey.Generate(parameterSet);
            mlDsaKey.Id = $"mldsa-{parameterSet}";
            var key = new Key(mlDsaKey);
            key.Id = mlDsaKey.Id;

            var opts = new CommonOptions();
            opts.Keys = new Key[] { key };

            // Create a sample body payload
            var body = new byte[1024];
            Random.Shared.NextBytes(body);

            var spec = YamlHelper.DeserializeSpec(SpecPath);
            var cg = ContextGraph.Read(spec, new MemoryStream(body), opts);

            // Act: Update computes digests and signatures, Check validates constraints
            cg.Update();
            cg.Check();

            // Assert: root has content (suppressed) + signature inject
            Assert.True(cg.Root.Members.Count == 2,
                $"Expected content and signature, but found {cg.Root.Members.Count} members of root.");

            // The signature inject node should contain the ML-DSA signature
            var sigNode = cg.Root.Members[1];
            Assert.Equal(expectedSigSize, sigNode.GetLength());

            // Write the signed output (signature only, content is suppressed)
            using var ms = new MemoryStream();
            cg.Write(ms);
            ms.Position = 0;
            var signedOutput = ms.ToArray();

            // Output is just the signature (content is suppressed/not written)
            Assert.Equal(expectedSigSize, signedOutput.Length);
        }

        /// <summary>
        /// E2E test: Signs a binary via the spec, then verifies the detached signature
        /// directly using Key.VerifySignature (raw-content-sign produces a detached signature).
        /// </summary>
        [Theory]
        [InlineData(MlDsaParameterSet.ML_DSA_44)]
        [InlineData(MlDsaParameterSet.ML_DSA_65)]
        [InlineData(MlDsaParameterSet.ML_DSA_87)]
        public void E2E_MlDsa_RoundtripVerifyTest(MlDsaParameterSet parameterSet)
        {
            // Arrange
            var mlDsaKey = MlDsaKey.Generate(parameterSet);
            mlDsaKey.Id = $"mldsa-{parameterSet}";
            var key = new Key(mlDsaKey);
            key.Id = mlDsaKey.Id;

            var opts = new CommonOptions();
            opts.Keys = new Key[] { key };

            var body = new byte[2048];
            Random.Shared.NextBytes(body);

            var spec = YamlHelper.DeserializeSpec(SpecPath);

            // Act: Sign — produces detached signature
            var signCg = ContextGraph.Read(spec, new MemoryStream(body), opts);
            signCg.Update();
            signCg.Check();

            using var ms = new MemoryStream();
            signCg.Write(ms);
            var signature = ms.ToArray();

            // Verify: compute the same SHA-256 digest the spec computes, then verify directly
            byte[] digest;
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                digest = sha256.ComputeHash(body);
            }

            // The spec signs the SHA-256 digest of the content via Key.SignHash
            bool verified = key.VerifySignature(digest, signature, isPssPadding: false);
            Assert.True(verified, "Detached ML-DSA signature should verify against the content digest.");
        }

        /// <summary>
        /// E2E test: Signs a binary with ML-DSA then attempts verification with a different key, expecting failure.
        /// </summary>
        [Fact]
        public void E2E_MlDsa_VerifyWithWrongKey_FailsTest()
        {
            // Arrange: sign with one key
            var signKey = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_65);
            signKey.Id = "mldsa-sign";
            var key1 = new Key(signKey);
            key1.Id = signKey.Id;

            var opts = new CommonOptions();
            opts.Keys = new Key[] { key1 };

            var body = new byte[512];
            Random.Shared.NextBytes(body);

            var spec = YamlHelper.DeserializeSpec(SpecPath);
            var signCg = ContextGraph.Read(spec, new MemoryStream(body), opts);
            signCg.Update();
            signCg.Check();

            using var ms = new MemoryStream();
            signCg.Write(ms);
            ms.Position = 0;

            // Act: attempt to verify with a different key
            var wrongKey = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_65);
            wrongKey.Id = "mldsa-wrong";
            var key2 = new Key(wrongKey);
            key2.Id = wrongKey.Id;

            var verifyOpts = new VerifyOptions();
            verifyOpts.Keys = new Key[] { key2 };

            // Assert: verification should fail
            Assert.ThrowsAny<Exception>(() =>
            {
                var verifyCg = ContextGraph.Read(spec, ms, verifyOpts);
                verifyCg.Check();
            });
        }

        /// <summary>
        /// Tests that the spec handles an empty body payload correctly.
        /// </summary>
        [Fact]
        public void E2E_MlDsa_EmptyBody_Test()
        {
            var mlDsaKey = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_44);
            mlDsaKey.Id = "mldsa-empty";
            var key = new Key(mlDsaKey);
            key.Id = mlDsaKey.Id;

            var opts = new CommonOptions();
            opts.Keys = new Key[] { key };

            var spec = YamlHelper.DeserializeSpec(SpecPath);
            var cg = ContextGraph.Read(spec, new MemoryStream(Array.Empty<byte>()), opts);

            cg.Update();
            cg.Check();

            using var ms = new MemoryStream();
            cg.Write(ms);

            // Output should be just the signature (ML-DSA-44 = 2420 bytes)
            Assert.Equal(2420, (int)ms.Length);
        }

        /// <summary>
        /// Tests that the signed_content digest correctly incorporates body changes.
        /// Signing two different bodies should produce different signatures.
        /// </summary>
        [Fact]
        public void E2E_MlDsa_DifferentBodies_ProduceDifferentSignatures()
        {
            var mlDsaKey = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_65);
            mlDsaKey.Id = "mldsa-diff";
            var key = new Key(mlDsaKey);
            key.Id = mlDsaKey.Id;

            var opts = new CommonOptions();
            opts.Keys = new Key[] { key };

            var spec = YamlHelper.DeserializeSpec(SpecPath);

            // Sign body 1
            var body1 = new byte[256];
            Array.Fill<byte>(body1, 0xAA);
            var cg1 = ContextGraph.Read(spec, new MemoryStream(body1), opts);
            cg1.Update();
            using var ms1 = new MemoryStream();
            cg1.Write(ms1);

            // Sign body 2
            var body2 = new byte[256];
            Array.Fill<byte>(body2, 0xBB);
            var cg2 = ContextGraph.Read(spec, new MemoryStream(body2), opts);
            cg2.Update();
            using var ms2 = new MemoryStream();
            cg2.Write(ms2);

            // The signed outputs should differ (different body content => different hash => different signature)
            var bytes1 = ms1.ToArray();
            var bytes2 = ms2.ToArray();
            Assert.False(bytes1.AsSpan().SequenceEqual(bytes2),
                "Signed binaries with different bodies should not be identical.");
        }
    }
}