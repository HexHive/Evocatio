## Overview

Here we present **POC Minimization**, **Critical Bytes Inference** and **CapFuzz**, which are based on AFL++. You can use these three parts either seperately or sequentially.

When using them sequentially, you may first trim original POC by **POC Minimization** to speed up subsequent procedure.  
Second, give the output of **POC Minimization** to **Critical Bytes Inference**, which will analyze critical input bytes for efficient **CapFuzz**.  
Third, make the most of the output of **POC Minimization** and **Critical Bytes Inference** to run **CapFuzz**, getting better results in most cases.

## Building

**Note: <project_path> stands for the directory of your project.**

To build, try:

```bash
cd /<project_path>/bug-severity-AFLplusplus/
make source-only NO_SPLICING=1
```

## Usage

You can go steps 1-2-3-4-5-6.  
For **POC Minimization** only, go steps 1-2-3-4.  
For **Critical Bytes Inference** only, go steps 1-2-3-5.  
For **CapFuzz** only, go steps 1-2-3-6.  
You can also use two of 4,5,6.

1. Prepare system environment and build *bug-severity-AFLplusplus*.

2. Get your target program and POC.

3. Revise target C file, insert following codes in the end of the file:

    ```C
    #include "sanitizer/asan_interface.h"
    #include "my_asan_on_error.h"
    void __asan_on_error() {
        __my_asan_on_error();
    }
    ```

    Then revise `instrument.sh` and compile target program:

    ```bash
    sh /<project_path>/instrument.sh

    # EXAMPLE:
    # sh /root/instrument.sh
    ```

    This step is used for instrumenting target program. You can also use other sanitizer as well. If so, please revise flags in `instrument.sh` adapting to your sanitizer.

4. **POC Minimization** (with `asan_afl_new.c`)

    Compile *lib*(CapSan) with `asan_afl_new.c` and compile target program:

    ```bash
    cp /<project_path>/lib/asan/afl/asan_afl_new.c /<project_path>/lib/asan/afl/asan_afl.c
    cd /<project_path>/lib/build
    cmake ..
    make
    sh /<project_path>/instrument.sh

    # EXAMPLE:
    # cp /root/lib/asan/afl/asan_afl_new.c /root/lib/asan/afl/asan_afl.c
    # cd /root/lib/build
    # cmake ..
    # make
    # sh /root/instrument.sh
    ```

    Trim original POC:

    ```bash
    ./<project_path>/bug-severity-AFLplusplus/afl-tmin-lazy -m none -i /path/to/original/poc -o /path/to/minimized/poc -- /path/to/target/program @@

    # EXAMPLE:
    # ./root/bug-severity-AFLplusplus/afl-tmin-lazy -m none -i /root/poc -o /root/poc_tmin -- /root/libtiff/tools/tiffcrop -H 341 @@ /tmp/foo
    ```

    "@@" is a placeholder like in AFL++. If there are any commands surrounding "@@", keep them.

5. **Critical Bytes Inference** (with `asan_afl_new.c`)

    Compile *lib*(CapSan) with `asan_afl_new.c` and compile target program:

    ```bash
    cp /<project_path>/lib/asan/afl/asan_afl_new.c /<project_path>/lib/asan/afl/asan_afl.c
    cd /<project_path>/lib/build
    cmake ..
    make
    sh /<project_path>/instrument.sh

    # EXAMPLE:
    # cp /root/lib/asan/afl/asan_afl_new.c /root/lib/asan/afl/asan_afl.c
    # cd /root/lib/build
    # cmake ..
    # make
    # sh /root/instrument.sh
    ```

    Analyze critical input bytes:

    ```bash
    mkdir /<project_path>/seeds
    AFL_TMIN_EXACT=1 /<project_path>/bug-severity-AFLplusplus/cd-bytes-identifier -m none -i /path/to/poc -o /tmp/foo -g -c /tmp/constraints.res -k /<project_path>/seeds/ -- /path/to/target/program @@

    # EXAMPLE:
    # mkdir /root/seeds
    # AFL_TMIN_EXACT=1 /root/bug-severity-AFLplusplus/cd-bytes-identifier -m none -i /root/poc -o /tmp/foo -g -c /tmp/constraints.res -k /root/seeds/ -- /root/libtiff/tools/tiffcrop -H 341 @@ /tmp/foo
    ```

    The output will be in `/<project_path>/seeds/`. If you'd like to use another fuzzer later, you may use seeds in `/<project_path>/seeds/` as your fuzzer's original seeds.

6. **CapFuzz** (with `asan_afl_ori.c`)

    Compile *lib*(CapSan) with `asan_afl_ori.c` and compile target program:

    ```bash
    cp /<project_path>/lib/asan/afl/asan_afl_ori.c /<project_path>/lib/asan/afl/asan_afl.c
    cd /<project_path>/lib/build
    cmake ..
    make
    sh /<project_path>/instrument.sh

    # EXAMPLE:
    # cp /root/lib/asan/afl/asan_afl_ori.c /root/lib/asan/afl/asan_afl.c
    # cd /root/lib/build
    # cmake ..
    # make
    # sh /root/instrument.sh
    ```

    Start CapFuzz:

    ```bash
    ./<project_path>/bug-severity-AFLplusplus/afl-fuzz -m none -C -i /path/to/input/seeds/ -o /path/to/output/ -k /path/to/original/poc -- /path/to/target/program @@

    # EXAMPLE:
    # mkdir /root/out_put
    # ./root/bug-severity-AFLplusplus/afl-fuzz -m none -C -i /root/seeds -o /root/out_put/ -k /root/poc -- /root/libtiff/tools/tiffcrop -H 341 @@ /tmp/foo
    ```

    If you didn't go step-5 before, just copy your POC or other seeds into `/path/to/input/seeds/`.

    Each new POC in the output directory represent a new capability found by CapFuzz.  Then you can summarize all new POCs to dipict bug capability.
    