var counter = 1

val freedVars = cpg.method
                .name("(.*_)?free")
                .filter(_.parameter.size == 1)
                .callIn
                .where(_.argument(1).isIdentifier)

val badDerefs = freedVars.flatMap(f => {
                    val freedIdentifierCode = f.argument(1).code
                    val postDom             = f.postDominatedBy.toSetImmutable

                    val assignedPostDom = postDom.isIdentifier
                    .where(_.inAssignment)
                    .codeExact(freedIdentifierCode)
                    .flatMap(id => id ++ id.postDominatedBy)

                    postDom
                    .removedAll(assignedPostDom)
})

badDerefs.foreach { d =>
    println(s"$counter: UAF candidate at ${d.file.name}:${d.lineNumber} => ${d.code}")
    counter += 1
}

println(s"\nTotal potential bugs: `${counter - 1}`")
