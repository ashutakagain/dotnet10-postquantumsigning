using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;   // SafeNCryptKeyHandle

namespace PostQuantum.MlDsa
{
    /// <summary>
    /// Signs / verifies ML-DSA data through a non-exportable CNG key handle (e.g. an HSM's
    /// Key Storage Provider) using the native Windows <c>ncrypt.dll</c> with the post-quantum
    /// DSA padding flag. Private key material never leaves the provider.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class CngHandleSigner
    {
        private const int NCRYPT_PAD_PQDSA_FLAG = 0x00000080;

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSignHash(
            SafeNCryptKeyHandle hKey,
            IntPtr pPaddingInfo,
            byte[] pbHashValue, int cbHashValue,
            byte[]? pbSignature, int cbSignature,
            out int pcbResult, int dwFlags);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptVerifySignature(
            SafeNCryptKeyHandle hKey,
            IntPtr pPaddingInfo,
            byte[] pbHashValue, int cbHashValue,
            byte[] pbSignature, int cbSignature,
            int dwFlags);

        public static byte[] Sign(CngKey key, byte[] message)
        {
            using (SafeNCryptKeyHandle h = key.Handle)
            {
                // 1st pass: length query (null signature buffer)
                int status = NCryptSignHash(h, IntPtr.Zero, message, message.Length,
                                            null, 0, out int cb, NCRYPT_PAD_PQDSA_FLAG);
                if (status != 0) throw new CryptographicException(status);

                // 2nd pass: actual sign
                var sig = new byte[cb];
                status = NCryptSignHash(h, IntPtr.Zero, message, message.Length,
                                        sig, sig.Length, out cb, NCRYPT_PAD_PQDSA_FLAG);
                if (status != 0) throw new CryptographicException(status);

                if (cb != sig.Length) Array.Resize(ref sig, cb);
                return sig;
            }
        }

        // Verifies an ML-DSA signature through the CNG/NCrypt provider handle (HSM public key).
        // Returns true only when the provider reports ERROR_SUCCESS (0). Never throws: if the
        // provider does not support verification (or any native error occurs) it returns false,
        // so the caller safely recomputes a fresh signature instead of crashing.
        public static bool Verify(CngKey key, byte[] message, byte[] signature)
        {
            if (key == null || message == null || signature == null)
                return false;

            try
            {
                using (SafeNCryptKeyHandle h = key.Handle)
                {
                    int status = NCryptVerifySignature(h, IntPtr.Zero,
                                                        message, message.Length,
                                                        signature, signature.Length,
                                                        NCRYPT_PAD_PQDSA_FLAG);
                    return status == 0;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
