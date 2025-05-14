/**
 * This CodeQl query detects for loops that use <= with an incrementing index variable, and for loops that use >= with an decrementing index variable
 * a common off-by-one pattern that can lead to out-of-bounds access when iterating over arrays or containers.
 */

import cpp

predicate isIndexVarInForwardLoop(ForStmt loop, Variable v)
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

predicate isIndexVarInBackwardLoop(ForStmt loop, Variable v)
{
  // Detect i = i - 1.
  exists(AssignExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getLValue() = v.getAnAccess()
  )
  or
  // Detect i -= 1.
  exists(AssignSubExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getLValue() = v.getAnAccess()
  )
  or
  // Detect i --.
  exists(PostfixDecrExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getOperand() = v.getAnAccess()
  )
  or
  // Detect -- i.
  exists(PrefixDecrExpr assign |
    assign.getEnclosingStmt().getParentStmt*() = loop and
    assign.getOperand() = v.getAnAccess()
  )
}

predicate isSuspiciousForwardLoopCondition(ForStmt loop, RelationalOperation cond, Variable indexVar)
{
  loop.getCondition() = cond and
  cond.getOperator() = "<="  and
  cond.getLeftOperand() = indexVar.getAnAccess() and
  isIndexVarInForwardLoop(loop, indexVar)
}

predicate isSuspiciousBackwardLoopCondition(ForStmt loop, RelationalOperation cond, Variable indexVar)
{
  loop.getCondition() = cond and
  cond.getOperator() = ">="  and
  cond.getLeftOperand() = indexVar.getAnAccess() and
  isIndexVarInBackwardLoop(loop, indexVar)
}

from ForStmt loop, Variable indexVar, RelationalOperation cond
where isSuspiciousForwardLoopCondition(loop, cond, indexVar) or isSuspiciousBackwardLoopCondition(loop, cond, indexVar)
select loop, "Suspicious loop using '<=' with index variable: " + indexVar.getName()
