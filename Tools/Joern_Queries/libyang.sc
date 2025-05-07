var counter = 1

val strcpy_calls = cpg.method
                .name("strcpy")
                .callIn

val strcpy_calls_info = strcpy_calls.flatMap{ call =>
    val dst = call.argument(1).code
    val src = call.argument(2).code
    val call_line = call.lineNumber
    val call_code = call.code
    val pre_doms = call.dominatedBy.toList

    pre_doms.map{ dom =>
        val dom_code = dom.code
        val dom_type = dom.getClass.getSimpleName
        (dst, src, dom_code, dom_type, call_line, call_code)
    }
}

val safe_strcpy_calls = strcpy_calls_info.filter{
    case (_, src, dom_code, dom_type, _, _)  =>
        (dom_type == "Call" || dom_type == "Method") &&
        dom_code.contains("strlen") &&
        dom_code.contains(s"strlen($src)")
}
.distinctBy{
    case (_, src, _, _, call_line, _) => (src, call_line)
}

safe_strcpy_calls.foreach{
    case (_, _, dom_code, dom_type, call_line, call_code) =>
        println(s"[$counter] Potentially unsafe use of strcpy() at line $call_line as $call_code")
        println(s"        ($dom_code, $dom_type)\n")
        counter += 1
}

println(s"\nTotal potential bugs: `${counter - 1}`")
