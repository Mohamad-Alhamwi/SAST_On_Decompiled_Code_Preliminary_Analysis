import cpp
import semmle.code.cpp.dataflow.new.DataFlow

// This query is taken from the original work available at:
// https://github.com/elManto/SAST_on_Decompilers/.
// We just updated it slightly to use the new Dataflow API.

from FunctionCall fc, Function f, FunctionCall src
where     f.hasName("memcpy") 
      and fc.getTarget() = f
      and src.getTarget().getName() = "calloc"
      and DataFlow::localFlow(DataFlow::exprNode(src),
          DataFlow::exprNode(fc.getArgument(0)))
select fc.getLocation()
