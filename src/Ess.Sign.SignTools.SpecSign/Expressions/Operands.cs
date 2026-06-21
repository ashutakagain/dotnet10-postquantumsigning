using System;

namespace Ess.Sign.SignTools.SpecSign.Expressions;

public interface IPropertyCapable
{
    Operand GetPropertyValue(string prop);
}

public abstract record Operand;

public sealed record StringOperand(string Value) : Operand
{
    public static StringOperand CreateString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new StringOperand(value);
    }
}

public sealed record BlobOperand(byte[] Value) : Operand
{
    public static BlobOperand CreateBlob(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new BlobOperand(value.ToArray());
    }
}

public sealed record NumericOperand(int Value) : Operand
{
    public static NumericOperand CreateNumeric(int value) => new(value);
}
