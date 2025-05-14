/**
 * This CodeQl query detects for loops that use <= with an incrementing index variable,
 * a common off-by-one pattern that can lead to out-of-bounds access when iterating over arrays or containers.
 */

import cpp

predicate isIndexVar(ForStmt loop, Variable v)
{
  // Detect i = i + 1.
  exists(AssignExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getLValue() = v.getAnAccess()
  )
  or
  // Detect i += 1.
  exists(AssignAddExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getLValue() = v.getAnAccess()
  )
  or
  // Detect i ++.
  exists(PostfixIncrExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getOperand() = v.getAnAccess()
  )
  or
  // Detect ++ i.
  exists(PrefixIncrExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getOperand() = v.getAnAccess()
  )
}

predicate isSuspiciousLoopCondition(ForStmt loop, RelationalOperation cond, Variable indexVar)
{
  loop.getCondition() = cond and
  cond.getOperator() = "<="  and
  cond.getLeftOperand() = indexVar.getAnAccess() and
  isIndexVar(loop, indexVar)
  //loop.getAnIterationVariable() = cond.getLeftOperand() and
}

from ForStmt loop, Variable indexVar, RelationalOperation cond
where isSuspiciousLoopCondition(loop, cond, indexVar)
select loop, "Suspicious loop using '<=' with index variable: " + indexVar.getName()
