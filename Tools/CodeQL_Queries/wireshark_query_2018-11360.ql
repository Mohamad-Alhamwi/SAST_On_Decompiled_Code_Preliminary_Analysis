/**
 * Detects loop index variables that are incremented and later used
 * in array indexing expressions.
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
  
module MyFlowConfiguration implements DataFlow::ConfigSig
{
  predicate isSource(DataFlow::Node source)
  {
    exists(ForStmt loop, Variable v |
      // Case 1: declared in the loop.
      // Does not detect Case 2: assigned in loop init, declared elsewhere.
      loop.getADeclaration() = v
      and
      source.asExpr() = v.getAnAccess()
    )
  }

  predicate isSink(DataFlow::Node sink)
  {
    exists(ArrayExpr array |
      sink.asExpr() = array.getArrayOffset()
    )
  }
}
 
module LoopIndexToArrayIndexFlow = TaintTracking::Global<MyFlowConfiguration>;

from  DataFlow::Node source, DataFlow::Node sink
where LoopIndexToArrayIndexFlow::flow(source, sink)
select sink, "Loop index flows into array index: source = " + source.toString()
  
// Expr getArrayBase().
