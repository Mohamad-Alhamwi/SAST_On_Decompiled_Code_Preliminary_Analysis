// This query finds cases where a loop index variable (initialized in a for-loop) 
// flows into an array index used outside any loop.

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
  
module MyFlowConfiguration implements DataFlow::ConfigSig
{
    predicate isSource(DataFlow::Node source)
    {
        exists(ForStmt loop, AssignExpr assignment, Variable v |
            loop.getInitialization().getAChild() = assignment
            and
            assignment.getLValue() = v.getAnAccess()
            and
            source.asExpr() = v.getAnAccess()
        )
    }
    
    predicate isSink(DataFlow::Node sink)
    {
        exists(ArrayExpr array | 
            sink.asExpr() = array.getArrayOffset()
            and not
            array.getBasicBlock().inLoop()
        )
    }
}
  
module LoopIndexToArrayIndexFlow = DataFlow::Global<MyFlowConfiguration>;

from  DataFlow::Node source, DataFlow::Node sink
where LoopIndexToArrayIndexFlow::flow(source, sink)
select sink, "Loop index flows into array index: source = " + source.toString()
