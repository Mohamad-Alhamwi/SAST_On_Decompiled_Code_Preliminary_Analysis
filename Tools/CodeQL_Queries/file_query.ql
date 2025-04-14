import cpp
import semmle.code.cpp.dataflow.DataFlow

// This query is taken from the original work available at:
// https://github.com/elManto/SAST_on_Decompilers/.

from FunctionCall fc, Expr src
where fc.getTarget().getName() = "memcpy"
    and DataFlow::localFlow(DataFlow::exprNode(src), 
    DataFlow::exprNode(fc.getArgument(2)))
select src
