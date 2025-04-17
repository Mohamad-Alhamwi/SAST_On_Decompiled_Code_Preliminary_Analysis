/**
 * @name Potentially unsafe use of strcpy().
 * @description Using 'strcpy' without checking the size of the source string may lead to buffer overflows.
 * @kind problem
 * @severity warning
 * @precision high
 * @id cpp/insecure/strcpy-no-size-check
 */

 import cpp

 predicate hasPriorLengthCheck(FunctionCall call)
 {
   exists(IfStmt cond |
     cond.getLocation().getStartLine() < call.getLocation().getStartLine() and
     exists(FunctionCall lenCall |
       lenCall.getTarget().hasGlobalOrStdName("strlen") and
       cond.getCondition().toString().matches("%strlen%")
     )
   )
 }
 
 predicate isUncheckedStrcpy(FunctionCall call)
 {
   call.getTarget().hasGlobalOrStdName("strcpy") and
   not hasPriorLengthCheck(call)
 }
 
 from FunctionCall call
 where isUncheckedStrcpy(call)
 select call, "Call to sscanf with no visible size check on the source string , which can cause a buffer overflow."
