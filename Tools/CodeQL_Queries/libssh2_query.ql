import cpp
import semmle.code.cpp.dataflow.new.DataFlow

// This query is taken from the original work available at:
// https://github.com/elManto/SAST_on_Decompilers/.
// We just updated it slightly to use the new Dataflow API.

  from MacroInvocation mi, Macro alloc, Expr src, AddExpr add
  where alloc.hasName("LIBSSH2_ALLOC") 
         and mi.getMacro() = alloc
         and mi.getExpr().(ExprCall).getArgument(0) = add
         and  DataFlow::localFlow(DataFlow::exprNode(src), 
              DataFlow::exprNode(mi.getExpr().(ExprCall).getArgument(0))
              )
         

  select src.getLocation(), mi
