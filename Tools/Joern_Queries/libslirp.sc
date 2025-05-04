var counter = 1

val freedVars = cpg.call.name("g_free").argument.isIdentifier

freedVars.foreach { freed =>
    val varName = freed.name
    val freeLine = freed.lineNumber.getOrElse(-1)
    val fileName = freed.file.name.headOption.getOrElse("")

    val badDerefs = cpg.call.name("<operator>.indirectFieldAccess")
        .argument.isIdentifier.name(varName)
        .filter(d => d.lineNumber.exists(_ > freeLine) && d.file.name.headOption.contains(fileName))

    badDerefs.foreach { d =>
        println(s"$counter: UAF candidate on `${varName}` at ${d.file.name}:${d.lineNumber} => ${d.code}")
        counter += 1
    }
}

println(s"\nTotal potential bugs: `${counter - 1}`")
    
