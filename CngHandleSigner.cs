using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;   // SafeNCryptKeyHandle

internal static class CngHandleSigner
{
    private const int NCRYPT_PAD_PQDSA_FLAG = 0x00000080;

    [DllImport("ncrypt.dll")]
    private static extern int NCryptSignHash(
        SafeNCryptKeyHandle hKey,
        IntPtr pPaddingInfo,
        byte[] pbHashValue, int cbHashValue,
        byte[] pbSignature, int cbSignature,
        out int pcbResult, int dwFlags);

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
}
