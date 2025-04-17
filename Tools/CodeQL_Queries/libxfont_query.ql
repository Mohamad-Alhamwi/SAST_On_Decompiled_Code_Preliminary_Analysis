/**
 * @name Potentially unsafe use of sscanf().
 * @description Using 'sscanf' without restricting format specifiers may lead to buffer overflows.
 * @kind problem
 * @severity warning
 * @precision high
 * @id cpp/insecure/sscanf
 */

 import cpp

 predicate hasUnboundedSscanfFormat(FunctionCall call) 
 {
     exists(StringLiteral fmt |
       call.getTarget().hasGlobalOrStdName("sscanf") and
       call.getArgument(1) = fmt and
       (
         fmt.getValue().matches("%s") or
         fmt.getValue().regexpMatch("%[^0-9]*s")
       )
     )
 }
 
from FunctionCall call
where hasUnboundedSscanfFormat(call)
select call, "Call to sscanf uses an unbounded %s format specifier, which can cause a stack-based buffer overflow."
