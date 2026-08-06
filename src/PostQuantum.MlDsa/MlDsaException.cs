using System;
using System.Collections.Generic;

namespace PostQuantum.MlDsa
{
    /// <summary>
    /// Classifies the kind of failure that occurred during an ML-DSA operation.
    /// </summary>
    public enum MlDsaErrorCode
    {
        Unknown = 0,
        NotSupported,
        InvalidArgument,
        InvalidKeyMaterial,
        ImportFailed,
        ExportFailed,
        SignFailed,
        VerifyFailed,
        PlatformCryptoFailure
    }

    /// <summary>
    /// Rich exception type for ML-DSA operations. Carries a structured <see cref="ErrorCode"/>
    /// plus optional operation / algorithm / context metadata, and mirrors everything into
    /// <see cref="Exception.Data"/> for logging systems that only capture that dictionary.
    /// </summary>
    public class MlDsaException : Exception
    {
        public MlDsaErrorCode ErrorCode { get; }
        public string? Operation { get; }
        public string? Algorithm { get; }
        public string? Context { get; }
        public IReadOnlyDictionary<string, string> DataBag { get; }

        public MlDsaException()
            : this(MlDsaErrorCode.Unknown, message: "An ML-DSA error occurred.")
        {
        }

        public MlDsaException(string message)
            : this(MlDsaErrorCode.Unknown, message)
        {
        }

        public MlDsaException(string message, Exception innerException)
            : this(MlDsaErrorCode.Unknown, message, innerException)
        {
        }

        public MlDsaException(
            MlDsaErrorCode errorCode,
            string message,
            Exception? innerException = null,
            string? operation = null,
            string? algorithm = null,
            string? context = null,
            IReadOnlyDictionary<string, string>? dataBag = null)
            : base(ComposeMessage(errorCode, message, operation, algorithm, context, dataBag), innerException)
        {
            ErrorCode = errorCode;
            Operation = operation;
            Algorithm = algorithm;
            Context = context;
            DataBag = dataBag ?? EmptyBag;

            base.Data[nameof(ErrorCode)] = ErrorCode.ToString();
            if (!string.IsNullOrWhiteSpace(Operation)) base.Data[nameof(Operation)] = Operation!;
            if (!string.IsNullOrWhiteSpace(Algorithm)) base.Data[nameof(Algorithm)] = Algorithm!;
            if (!string.IsNullOrWhiteSpace(Context)) base.Data[nameof(Context)] = Context!;
            foreach (var kvp in DataBag)
            {
                base.Data[$"Bag.{kvp.Key}"] = kvp.Value;
            }
        }

        /// <summary>
        /// Wraps an arbitrary exception as an <see cref="MlDsaException"/>, preserving the original
        /// as <see cref="Exception.InnerException"/>. If <paramref name="ex"/> is already an
        /// <see cref="MlDsaException"/> it is returned unchanged.
        /// </summary>
        public static MlDsaException Wrap(
            MlDsaErrorCode code,
            string operation,
            Exception ex,
            string? algorithm = null,
            string? context = null,
            IReadOnlyDictionary<string, string>? bag = null)
        {
            if (ex is MlDsaException already) return already;

            var msg = $"ML-DSA operation '{operation}' failed.";
            return new MlDsaException(code, msg, ex, operation: operation, algorithm: algorithm, context: context, dataBag: bag);
        }

        private static string ComposeMessage(
            MlDsaErrorCode code,
            string message,
            string? operation,
            string? algorithm,
            string? context,
            IReadOnlyDictionary<string, string>? bag)
        {
            var parts = new List<string>(capacity: 6)
            {
                $"[{code}] {message}"
            };

            if (!string.IsNullOrWhiteSpace(operation)) parts.Add($"Op={operation}");
            if (!string.IsNullOrWhiteSpace(algorithm)) parts.Add($"Algo={algorithm}");
            if (!string.IsNullOrWhiteSpace(context)) parts.Add($"Ctx={context}");

            if (bag is { Count: > 0 })
            {
                foreach (var kvp in bag)
                {
                    parts.Add($"{kvp.Key}={kvp.Value}");
                }
            }

            return string.Join(" ", parts);
        }

        private static readonly IReadOnlyDictionary<string, string> EmptyBag =
            new Dictionary<string, string>(0);
    }
}
