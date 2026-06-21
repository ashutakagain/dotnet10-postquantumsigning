using System;

namespace Ess.Sign.SignTools.SpecSign.Crypto.MLDsa;

public enum MlDsaErrorCode
{
    InvalidArgument = 1,
    InvalidOperation = 2
}

public sealed class MlDsaException : Exception
{
    public MlDsaException(string message)
        : base(message)
    {
    }

    public MlDsaException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public MlDsaException(MlDsaErrorCode errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode;
    }

    public MlDsaErrorCode? ErrorCode { get; }
}
