// This script detects whether arguments of memcpy were validated using comparison operators
// before the actual call to memcpy.

importCpg("cpg.bin")

// Step 1: Get all arguments passed to memcpy
val memcpyArgs = cpg.call.name("memcpy").argument.reachableBy(cpg.identifier).toSet

// Step 2: Look for comparison calls like <, >, <=, >=
val comparisonCalls = cpg.call.name(".*less.*", ".*greater.*", ".*equals.*").argument.reachableBy(memcpyArgs).toSet

// Step 3: Check if any of the same identifiers are used in both memcpy and in comparisons
val validatedInputs = memcpyArgs.intersect(comparisonCalls).asInstanceOf[Set[Call]]

// Step 4: Report them — show what was checked
validatedInputs.foreach { call =>
  println(s"Possibly validated input before memcpy: '${call.code}' at line ${call.lineNumber.getOrElse("?" )}")
}
