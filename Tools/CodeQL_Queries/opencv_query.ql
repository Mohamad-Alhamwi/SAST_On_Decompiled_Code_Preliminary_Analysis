// This query is taken from the original work available at:
// https://github.com/elManto/SAST_on_Decompilers/.
// We just updated it slightly to use the new TaintTracking API.

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

module MyFlowConfiguration implements DataFlow::ConfigSig
{
    predicate isSource(DataFlow::Node source)
    {
        exists (Expr e | source.asExpr() = e)
    }

    predicate isSink(DataFlow::Node sink)
    {
        exists (FunctionCall fc | 
            fc.getTarget().hasGlobalOrStdName("memcpy") and
            sink.asExpr() = fc.getArgument(2))

        and not sink.asExpr().isConstant()
    }
}

module MyFlow = TaintTracking::Global<MyFlowConfiguration>;

predicate sourceSized(FunctionCall fc, Expr src)
{
    fc.getTarget().hasGlobalOrStdName("memcpy") and
    exists(Expr dest, Expr size, Variable v |
        fc.getArgument(0) = dest and
        fc.getArgument(1) = src and
        fc.getArgument(2) = size and
        src = v.getAnAccess() and
        size.getAChild+() = v.getAnAccess() and
        // Exception: dest is referenced in size
        not exists(Variable other | dest = other.getAnAccess() and size.getAChild+() = other.getAnAccess())
        and
        // Exception: src and dest are same-sized arrays of same base type
        not exists(ArrayType srctype, ArrayType desttype |
            dest.getType().getUnderlyingType() = desttype and
            src.getType().getUnderlyingType() = srctype and
            desttype.getBaseType().getUnderlyingType() = srctype.getBaseType().getUnderlyingType() and
            desttype.getArraySize() = srctype.getArraySize()
        )
    )
}

from FunctionCall memcpyCall, DataFlow::Node source, DataFlow::Node sink
where
    MyFlow::flow(source, sink)
    and
    memcpyCall.getTarget().hasGlobalOrStdName("memcpy")
    and
    sink.asExpr() = memcpyCall.getArgument(2)
    and
    sourceSized(memcpyCall, memcpyCall.getArgument(1))
select sink.asExpr(), source.asExpr(), sink.asExpr(),
    "Source expression '" + source.asExpr().toString() + "' flows into memcpy sink '" + sink.asExpr().toString() + "'."
