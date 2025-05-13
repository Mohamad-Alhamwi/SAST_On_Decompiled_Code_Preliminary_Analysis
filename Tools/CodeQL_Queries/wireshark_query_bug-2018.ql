import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

// This query is taken from the original work available at:
// https://github.com/elManto/SAST_on_Decompilers/.
// We have just made slight updates to adapt it to the new Dataflow API.

module MyFlowConfiguration implements DataFlow::ConfigSig
{
    predicate isSource(DataFlow::Node source)
    {
        exists (Expr e | source.asExpr() = e)
    }

    predicate isSink(DataFlow::Node sink)
    {
        exists (FunctionCall fc | 
            fc.getTarget().getQualifiedName() = "g_free" and
            sink.asExpr() = fc.getArgument(0).(VariableAccess).getQualifier().(VariableAccess).getQualifier()
        )
    }
}

module MyFlow = TaintTracking::Global<MyFlowConfiguration>;

from  DataFlow::Node source, DataFlow::Node sink
where MyFlow::flow(source, sink)
select source, sink, "Flow to free"

