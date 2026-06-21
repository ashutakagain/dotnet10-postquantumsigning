using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Ess.Sign.SignTools.SpecSign.Crypto.MLDsa;

[SupportedOSPlatform("windows")]
internal static partial class CngHandleSigner
{
    private const int NcryptPqdsaPaddingFlag = 0x00000080;

    public static byte[] Sign(CngKey key, byte[] data)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(data);

        bool addedRef = false;

        try
        {
            key.Handle.DangerousAddRef(ref addedRef);

            var keyHandle = key.Handle.DangerousGetHandle();
            ThrowIfError(NCryptSignHash(keyHandle, IntPtr.Zero, data, data.Length, null, 0, out var signatureSize, NcryptPqdsaPaddingFlag));

            var signature = new byte[signatureSize];
            ThrowIfError(NCryptSignHash(keyHandle, IntPtr.Zero, data, data.Length, signature, signature.Length, out signatureSize, NcryptPqdsaPaddingFlag));

            if (signature.Length == signatureSize)
            {
                return signature;
            }

            Array.Resize(ref signature, signatureSize);
            return signature;
        }
        finally
        {
            if (addedRef)
            {
                key.Handle.DangerousRelease();
            }
        }
    }

    private static void ThrowIfError(int errorCode)
    {
        if (errorCode != 0)
        {
            throw new CryptographicException(errorCode);
        }
    }

    [LibraryImport("ncrypt.dll")]
    private static partial int NCryptSignHash(
        IntPtr hKey,
        IntPtr pPaddingInfo,
        byte[] pbHashValue,
        int cbHashValue,
        byte[]? pbSignature,
        int cbSignature,
        out int pcbResult,
        int dwFlags);
}
