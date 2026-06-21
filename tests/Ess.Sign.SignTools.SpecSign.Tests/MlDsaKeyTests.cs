using System;
using System.IO;
using System.Security.Cryptography;
using Ess.Sign.SignTools.SpecSign.Context;
using Ess.Sign.SignTools.SpecSign.Crypto.MLDsa;
using Ess.Sign.SignTools.SpecSign.Expressions;

#pragma warning disable SYSLIB5006

namespace Ess.Sign.SignTools.SpecSign.Tests;

public sealed class MlDsaKeyTests
{
    [Theory]
    [InlineData(MlDsaParameterSet.ML_DSA_44)]
    [InlineData(MlDsaParameterSet.ML_DSA_65)]
    [InlineData(MlDsaParameterSet.ML_DSA_87)]
    public void Generate_SignAndVerify_RoundTrips(MlDsaParameterSet parameterSet)
    {
        using var key = MlDsaKey.Generate(parameterSet);
        byte[] hash = [1, 2, 3, 4, 5, 6, 7, 8];

        var signature = key.SignHash(hash);

        Assert.Equal(parameterSet, key.ParameterSet);
        Assert.True(key.HasPrivate);
        Assert.Equal(key.SignatureSize, signature.Length);
        Assert.True(key.VerifySignature(hash, signature));
    }

    [Theory]
    [InlineData(MlDsaParameterSet.ML_DSA_44, true)]
    [InlineData(MlDsaParameterSet.ML_DSA_44, false)]
    [InlineData(MlDsaParameterSet.ML_DSA_65, true)]
    [InlineData(MlDsaParameterSet.ML_DSA_87, false)]
    public void ByteArrayConstructor_ImportsExpectedKeyKind(MlDsaParameterSet parameterSet, bool usePrivateKey)
    {
        using var algorithm = System.Security.Cryptography.MLDsa.GenerateKey(ToAlgorithm(parameterSet));
        var keyBytes = usePrivateKey
            ? algorithm.ExportPkcs8PrivateKey()
            : algorithm.ExportSubjectPublicKeyInfo();

        using var key = new MlDsaKey(keyBytes, parameterSet, usePrivateKey);

        Assert.Equal(parameterSet, key.ParameterSet);
        Assert.Equal(usePrivateKey, key.HasPrivate);

        var publicKey = Assert.IsType<BlobOperand>(key.GetPropertyValue("publickey"));
        Assert.NotEmpty(publicKey.Value);
    }

    [Fact]
    public void FileConstructor_LoadsPemPrivateKey()
    {
        using var algorithm = System.Security.Cryptography.MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():N}.pem");

        try
        {
            File.WriteAllText(path, algorithm.ExportPkcs8PrivateKeyPem());

            using var key = new MlDsaKey(path);

            Assert.Equal(MlDsaParameterSet.ML_DSA_65, key.ParameterSet);
            Assert.True(key.HasPrivate);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void PlaceholderSignature_WritesDigestFile()
    {
        using var key = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_44);
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        byte[] hash = [9, 8, 7, 6];
        var context = new NodeContext
        {
            Structure = new NodeStructure
            {
                Name = "sample/node"
            }
        };

        context.NonFileContext.PlaceholderDigestPathBase = directory;

        try
        {
            var signature = key.SignHash(hash, context);
            var expectedFile = Path.Combine(directory, $"sample_node_{Sanitize(key.Id ?? "anonymous")}.mldsa.b64");

            Assert.True(File.Exists(expectedFile));
            Assert.Equal(Convert.ToBase64String(hash), File.ReadAllText(expectedFile));
            Assert.True(key.VerifySignature(hash, signature, context));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public void GetPropertyValue_ExposesAlgorithmMetadata()
    {
        using var key = MlDsaKey.Generate(MlDsaParameterSet.ML_DSA_87);

        var algorithm = Assert.IsType<StringOperand>(key.GetPropertyValue("algorithm"));
        var securityLevel = Assert.IsType<NumericOperand>(key.GetPropertyValue("securitylevel"));
        var spki = Assert.IsType<BlobOperand>(key.GetPropertyValue("spki"));

        Assert.Equal("ML-DSA-87", algorithm.Value);
        Assert.Equal(5, securityLevel.Value);
        Assert.NotEmpty(spki.Value);
    }

    private static MLDsaAlgorithm ToAlgorithm(MlDsaParameterSet parameterSet)
    {
        return parameterSet switch
        {
            MlDsaParameterSet.ML_DSA_44 => MLDsaAlgorithm.MLDsa44,
            MlDsaParameterSet.ML_DSA_65 => MLDsaAlgorithm.MLDsa65,
            MlDsaParameterSet.ML_DSA_87 => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(parameterSet), parameterSet, null)
        };
    }

    private static string Sanitize(string value)
    {
        foreach (var invalidChar in Path.GetInvalidFileNameChars())
        {
            value = value.Replace(invalidChar, '_');
        }

        return value;
    }
}
