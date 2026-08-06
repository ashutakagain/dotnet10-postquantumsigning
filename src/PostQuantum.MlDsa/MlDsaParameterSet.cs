namespace PostQuantum.MlDsa
{
    /// <summary>
    /// ML-DSA parameter sets as defined in NIST FIPS 204.
    /// The numeric values match the parameter-set suffix (44 / 65 / 87).
    /// </summary>
    public enum MlDsaParameterSet
    {
        /// <summary>ML-DSA-44 — NIST Security Level 2 (comparable to AES-128).</summary>
        ML_DSA_44 = 44,

        /// <summary>ML-DSA-65 — NIST Security Level 3 (comparable to AES-192).</summary>
        ML_DSA_65 = 65,

        /// <summary>ML-DSA-87 — NIST Security Level 5 (comparable to AES-256).</summary>
        ML_DSA_87 = 87
    }
}
