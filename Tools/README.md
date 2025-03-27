# Tools

## Tools List

- Clang (10.0.0-4ubuntu1).
- Infer ().
- Cppcheck ().

## Tools Workflow

### Clang Workflow
When using the **Clang Static Analyzer**, configuration scripts and build system generator tools (like `./configure` or `cmake`) should also be run through the analyzer. These scripts often generate **Makefiles** with hardcoded compiler paths. Running them through the **Clang Static Analyzer** ensures that the compiler path is set to **ccc-analyzer**, allowing all subsequent build steps to be properly analyzed.

We used the following commands to run the analysis:
```C
scan-build ./configure
scan-build -v --keep-going  --force-analyze-debug-code -o . make -j$(nproc)
```

The analysis was performed with these Clang checkers enabled:

```C
-enable-checker alpha.security.taint.TaintPropagation
-enable-checker alpha.security.ArrayBound
-enable-checker security.insecureAPI.strcpy
-enable-checker security.insecureAPI.DeprecatedOrUnsafeBufferHandling
```

### Infer Workflow

**Problem:**

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

**Solution:**

Instead, we used the following approach:

```C
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1
infer run --compilation-database compile_commands.json --keep-going
```

For projects that do not contain the `CMakeLists.txt` file, we used `bear` along with `make` to generate the `compile_commands.json` file:
```C
bear make -j$(nproc)
infer run --compilation-database compile_commands.json --keep-going
```

**Explanation:**
- The `-DCMAKE_EXPORT_COMPILE_COMMANDS=1` flag tells **CMake** to generate a `compile_commands.json` file in the build directory.
- This file serves as a JSON compilation database, listing all the compile commands used to build the project.
- Infer reads from `compile_commands.json` instead of intercepting the build process directly, making it more robust and reliable in cases where direct compilation interception fails.
- The `--keep-going` flag ensures that Infer continues running even if it encounters minor failures during analysis.

### Cppcheck Workflow
Cppcheck can analyze projects either manually by specifying files/paths to check and settings, or by using a build environment such as CMake. According to its official documentation, it is recommended to use both approaches for better results. So we used both methods to analyze the projects.

**Mannual Approach:**

We ran
```C
cppcheck --verbose --enable=all . --output-file=cppcheck_report_manual.txt
```

**Build Environment Approach:**

We ran
```C
mkdir build && cd build
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
cppcheck --verbose --enable=all --project=compile_commands.json --output-file=cppcheck_report_build.txt
```

**Explanation:**
- The `--output-file=<file>` option writes results to file, rather than standard error.
- The `--verbose` option outputs more detailed error information.
- The `--enable=all` option enables all available checks
- The `.` in the manuall approach means *analize the source files in this directory*, while `--project=compile_commands.json` in the build-based approach means *use the compile database* to conduct analysis.

