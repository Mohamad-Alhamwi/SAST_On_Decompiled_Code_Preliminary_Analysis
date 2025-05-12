var counter = 1

// Get all assignments where RHS contains a division.
val divisions = cpg.call.name("<operator>.assignment")
                .where(_.argument(2).code(".* / .*"))
                .map(division =>(
                    "at " + division.location.filename + ":" + division.location.lineNumber.get + " ==> " + "'" + division.code + "'"
                ))

divisions.foreach{ div =>

    println(s"$counter: A potential divide by zero candidate ${div}")

    counter += 1
}

println(s"\nTotal potential bugs: ${counter - 1}") 
