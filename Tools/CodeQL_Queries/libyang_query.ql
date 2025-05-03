/**
 * @name Potentially unsafe use of strcpy().
 * @description Using 'strcpy' without checking the size of the source string may lead to buffer overflows.
 * @kind problem
 * @severity warning
 * @precision high
 * @id cpp/insecure/strcpy-no-size-check
 */

import cpp

/** 
 * Returns true if this function call is a call to "strcpy".
 */
predicate isStrcpy(FunctionCall call)
{
    call.getTarget().hasGlobalOrStdName("strcpy")
}

/** 
 * Returns true if this function call is a call to "strlen(src)", where "src" is the second argument to "strcpy".
 */
predicate isStrlen(FunctionCall call, Expr sourceArg)
{
    call.getTarget().hasGlobalOrStdName("strlen") and
    call.getArgument(0) = sourceArg
}

predicate hasLengthCheckBefore(FunctionCall strcpyCall) 
{
    exists(FunctionCall strlenCall, IfStmt ifStmt, Expr sourceArg |
        sourceArg = strcpyCall.getArgument(1) and
        isStrlen(strlenCall, sourceArg) and
    
        ifStmt.getLocation().getEndLine() + 1 = strcpyCall.getLocation().getStartLine() and
    
        strlenCall = ifStmt.getCondition().(Expr).getAChild*()
    )

    or

    exists(FunctionCall strlenCall, ExprStmt stmtBefore, Expr sourceArg |
        sourceArg = strcpyCall.getArgument(1) and
        isStrlen(strlenCall, sourceArg) and
  
        stmtBefore.getExpr() = strlenCall and
        stmtBefore.getLocation().getEndLine() + 1 = strcpyCall.getLocation().getStartLine()
    )

    or

    exists(FunctionCall strlenCall, Expr sourceArg |
        sourceArg = strcpyCall.getArgument(1) and
        isStrlen(strlenCall, sourceArg) and
    
        strlenCall.isInMacroExpansion() and
        strlenCall.getLocation().getStartLine() + 1 = strcpyCall.getLocation().getStartLine()
    )
}

/**
 * Matches strcpy calls that are not preceded by a length check on their source.
 */
predicate isUncheckedStrcpy(FunctionCall call)
{
    isStrcpy(call) and
    not hasLengthCheckBefore(call)
}

from FunctionCall call
where isUncheckedStrcpy(call)
select call, "Call to strcpy with no visible size check on the source string, which can cause a buffer overflow."

