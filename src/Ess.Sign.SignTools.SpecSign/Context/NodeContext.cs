using System;

namespace Ess.Sign.SignTools.SpecSign.Context;

public sealed class NodeContext
{
    public NodeContext()
    {
        ContextGraph = new ContextGraph(NonFileContext);
    }

    public NonFileContext NonFileContext { get; } = new();

    public ContextGraph ContextGraph { get; }

    public NodeStructure Structure { get; init; } = new();
}

public sealed class ContextGraph
{
    public ContextGraph(NonFileContext nonFileContext)
    {
        NonFileContext = nonFileContext ?? throw new ArgumentNullException(nameof(nonFileContext));
    }

    public NonFileContext NonFileContext { get; }
}

public sealed class NonFileContext
{
    public string? PlaceholderDigestPathBase { get; set; }
}

public sealed class NodeStructure
{
    public string Name { get; init; } = "node";
}
