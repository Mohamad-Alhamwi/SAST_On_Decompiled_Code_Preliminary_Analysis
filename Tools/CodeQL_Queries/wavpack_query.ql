import cpp
import semmle.code.cpp.dataflow.DataFlow

// This query is taken from the original work available at:
// https://github.com/elManto/SAST_on_Decompilers/.

from DivExpr div, VariableAccess va
where DataFlow::localFlow(DataFlow::exprNode(va),
   DataFlow::exprNode(div.getRightOperand()))
select div, va
