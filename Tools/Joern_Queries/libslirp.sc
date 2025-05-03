// Select all function calls in the codebase ==> filter to only those calls named "g_free" ==> grabs all arguments passed to "g_free" calls.
val freedVars = cpg.call.name("g_free").argument.filter(_.lineNumber == Some(113))
freedVars.foreach(x => println(s"${x.file.name}:${x.lineNumber} => ${x.code}"))

// Select all function calls in the codebase ==> filter down to only operations.
val derefs = cpg.call.name("<operator>.indirectFieldAccess").filter(_.lineNumber == Some(114))
derefs.foreach(x => println(s"${x.file.name}:${x.lineNumber} => ${x.code}"))
