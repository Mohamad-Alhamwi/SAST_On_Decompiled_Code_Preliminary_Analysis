var counter = 1

// Find all calls to strcpy.
val strcpy_calls = cpg.method
                .name("strcpy")
                .callIn

// Get all strcpy calls that are not preceded by "strlen" using the same source.
val unsafe_strcpy_calls = strcpy_calls.filterNot{ call =>
    val src_Arg = call.argument(2)
    val prev = call.method.ast.isCall.name("strlen")
    .filter(strlen => strlen.argument(1).code == src_Arg.code)
    .filter(strlen => strlen.lineNumber.getOrElse(0) < call.lineNumber.getOrElse(Int.MaxValue))
    
    prev.nonEmpty
}

unsafe_strcpy_calls.foreach{ call =>
    val call_line = call.lineNumber.getOrElse(-1)
    val call_code = call.code
    println(s"[$counter] Potentially unsafe use of strcpy() at line $call_line: $call_code")

    counter += 1
}

println(s"\nTotal potential bugs: ${counter - 1}")
