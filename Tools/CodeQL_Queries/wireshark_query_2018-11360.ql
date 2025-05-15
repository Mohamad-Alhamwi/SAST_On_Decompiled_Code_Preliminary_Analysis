/**
 * Detects loop index variables that are:
 * 1. Declared either inside or before the loop statement, and
 * 2. Incremented in the loop's update clause or body,
 * and are later used in array indexing expressions.
 */


import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
  
module MyFlowConfiguration implements DataFlow::ConfigSig
{
  predicate isSource(DataFlow::Node source)
  {
    // Case 1: Declared in the loop, for(int i = 0;;).
    exists(ForStmt loop, Variable v |
      loop.getADeclaration() = v and
      source.asExpr() = v.getAnAccess() and
      (
        // Variable used in update clause.
        exists(Expr update |
          loop.getUpdate() = update and
          update.getAChild*() = v.getAnAccess()
        )
        or
        // Variable incremented in loop body.
        (
          // i = i + 1
          exists(AssignExpr assign |
            assign.getLValue() = v.getAnAccess() and
            assign.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
          or
          // i += 1
          exists(AssignAddExpr assign |
            assign.getLValue() = v.getAnAccess() and
            assign.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
          or
          // i++
          exists(PostfixIncrExpr inc |
            inc.getOperand() = v.getAnAccess() and
            inc.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
          or
          // ++i
          exists(PrefixIncrExpr inc |
            inc.getOperand() = v.getAnAccess() and
            inc.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
        )
      )
    )
    or
    // Case 2: Assigned in loop init, declared elsewhere, for(i = 0;;).
    exists(ForStmt loop, Variable v |
      source.asExpr() = v.getAnAccess() and
      exists(AssignExpr initAssign |
        loop.getInitialization().getAChild*() = initAssign and
        initAssign.getLValue() = v.getAnAccess()
      ) and
      (
        // Variable used in update clause.
        exists(Expr update |
          loop.getUpdate() = update and
          update.getAChild*() = v.getAnAccess()
        )
        or
        // Variable incremented in loop body.
        (
          exists(AssignExpr assign |
            assign.getLValue() = v.getAnAccess() and
            assign.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
          or
          exists(AssignAddExpr assign |
            assign.getLValue() = v.getAnAccess() and
            assign.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
          or
          exists(PostfixIncrExpr inc |
            inc.getOperand() = v.getAnAccess() and
            inc.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
          or
          exists(PrefixIncrExpr inc |
            inc.getOperand() = v.getAnAccess() and
            inc.getEnclosingStmt().getParentStmt*() = loop.getStmt()
          )
        )
      )
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
