var counter = 1

val strcpy_calls = cpg.method
                .name("strcpy")
                .callIn
                .filter(_.parameter.size == 2)

val unsafe_strcpy_calls = strcpy_calls.flatMap(c => {
    val dist_arg = c.argument(0).code
    val src_arg = c.argument(1).code

    val pre_dom = c.dominates.toSetImmutable

    pre_dom
    .isCall
    .name("strlen")
    .argument(0)
    .codeExact(src_arg)
})

unsafe_strcpy_calls.foreach { d =>
    println(s"$counter: Potentially unsafe use of strcpy(). at ${d.file.name}:${d.lineNumber} => ${d.code}")
    counter += 1
}

println(s"\nTotal potential bugs: `${counter - 1}`")
