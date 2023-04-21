## Overview

Here we present **POC Minimization**, **Critical Bytes Inference** and **CapFuzz**, which are based on AFL++. You can use these three parts either seperately or sequentially.

When using them sequentially, you may first trim original POC by **POC Minimization** to speed up subsequent procedure.  
Second, give the output of **POC Minimization** to **Critical Bytes Inference**, which will analyze critical input bytes for efficient **CapFuzz**.  
Third, make the most of the output of **POC Minimization** and **Critical Bytes Inference** to run **CapFuzz**, getting better results in most cases.

## Building

Just build *bug-severity-AFLplusplus* like what is needed for *afl++*:

```bash
make source-only NO_SPLICING=1
```

:warning: Warning:

 - Ensure that `NO_SPLICING=1` is always used there.

 - Never use `ASAN_BUILD=1`. Otherwise our *bug-severity run-time dependency* may confuse your compiler and linker, as well as AddressSanitizer.

 - Since *afl++ 3.0* there is only one compiler *afl-cc* works for instrumenting your target, all previous compilers now symlink to it. We have hacked it so that our *bug-severity run-time dependency* can be linked into the target binary. If *afl-cc* couldn't be built and work properly, then all is over.

## Usage

You can go steps 1-2-3-4-5-6.  
For **POC Minimization** only, go steps 1-2-3-4.  
For **Critical Bytes Inference** only, go steps 1-2-3-5.  
For **CapFuzz** only, go steps 1-2-3-6.  
You can also use two of 4,5,6.

1. Install dependencies and build *bug-severity-AFLplusplus*.

2. Get your target program and POC.

3. Compile and instrument your target program with *AddressSanitizer* enabled just as same as when using *afl++*.
   
   :warning: Ensure that *AddressSanitizer* is applied for your target. It is strongly recommended that set the environment variable `AFL_USE_ASAN=1` to tell  *afl-cc* do everything for you. Manually using compiler flag `-fsanitize=address` as [the doc says](https://github.com/google/sanitizers/wiki/AddressSanitizer) is also an alternative. 

4. **POC Minimization**

    Trim original POC:

    ```bash
    ./<project_path>/bug-severity-AFLplusplus/afl-tmin-lazy -m none -i /path/to/original/poc -o /path/to/minimized/poc -- /path/to/target/program @@

    # EXAMPLE:
    # ./root/bug-severity-AFLplusplus/afl-tmin-lazy -m none -i /root/poc -o /root/poc_tmin -- /root/libtiff/tools/tiffcrop -H 341 @@ /tmp/foo
    ```

    "@@" is a placeholder like in AFL++. If there are any commands surrounding "@@", keep them.

5. **Critical Bytes Inference**

    Analyze critical input bytes:

    ```bash
    mkdir /<project_path>/seeds
    /<project_path>/bug-severity-AFLplusplus/cd-bytes-identifier -m none -i /path/to/poc -o /tmp/foo -g -c /tmp/constraints.res -k /<project_path>/seeds/ -- /path/to/target/program @@

    # EXAMPLE:
    # mkdir /root/seeds
    # /root/bug-severity-AFLplusplus/cd-bytes-identifier -m none -i /root/poc -o /tmp/foo -g -c /tmp/constraints.res -k /root/seeds/ -- /root/libtiff/tools/tiffcrop -H 341 @@ /tmp/foo
    ```

    The output will be in `/<project_path>/seeds/`. If you'd like to use another fuzzer later, you may use seeds in `/<project_path>/seeds/` as your fuzzer's original seeds.

6. **CapFuzz**

    Start CapFuzz:

    ```bash
    ./<project_path>/bug-severity-AFLplusplus/afl-fuzz -m none -C -i /path/to/input/seeds/ -o /path/to/output/ -k /path/to/original/poc -- /path/to/target/program @@

    # EXAMPLE:
    # mkdir /root/out_put
    # ./root/bug-severity-AFLplusplus/afl-fuzz -m none -C -i /root/seeds -o /root/out_put/ -k /root/poc -- /root/libtiff/tools/tiffcrop -H 341 @@ /tmp/foo
    ```

    If you didn't go step-5 before, just copy your POC or other seeds into `/path/to/input/seeds/`.

    Each new POC in the output directory represent a new capability found by CapFuzz.  Then you can summarize all new POCs to dipict bug capability.
    