/**
 * @name stack-based buffer overflow vulnerability due to unbounded format string in sscanf call.
 * @kind problem
 * @severity warning
 * @precision high
 * @id cpp/insecure/sscanf-missing-size
 */

 import cpp

 // A query to detect `sscanf` calls with an unbounded `%s` format specifier.
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