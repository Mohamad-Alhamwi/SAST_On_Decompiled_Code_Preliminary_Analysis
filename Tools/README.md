# Tools List

## Infer

**Problem**

Running
```C
cmake ..
infer run -- make -j$(nproc)
```
sometimes fails, displaying the following message without generating any reports:

> Nothing to compile. Try running make `clean first`.
>
> There was nothing to analyze.
>
> No issues found

**Solution**

Instead, we used the following approach:

```C
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1
infer run --compilation-database compile_commands.json --keep-going
```

**Explanation**
- The `-DCMAKE_EXPORT_COMPILE_COMMANDS=1` flag tells **CMake** to generate a `compile_commands.json` file in the build directory.
- This file serves as a JSON compilation database, listing all the compile commands used to build the project.
- Infer reads from `compile_commands.json` instead of intercepting the build process directly. Which is the robust making it more reliable in cases where direct compilation interception fails.
- The `--keep-going` flag ensures that Infer continues running even if it encounters minor failures during analysis.






