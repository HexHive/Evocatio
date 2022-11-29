# Evocatio

## Overview

Evocatio is a bug analyzer built on top of AFL++ and AddressSanitizer. It automatically discovers a bug’s capabilities: analyzing a crashing test case (i.e., an input exposing a bug) to understand the full extent of how an attacker can exploit a bug. Evocatio leverages a capability-guided fuzzer to efficiently uncover new bug capabilities (rather than only generating a single crashing test case for a given bug, as a traditional greybox fuzzer does).

In this repo, we present 5 function module of Evocatio:

- **POC Minimization**: to get a poc with smaller size like afl-tmin.
- **Critical Bytes Inference**: to infer which bytes of poc are critical, so as to mutate them first.
- **CapFuzz**: to explore new capabilities of a bug. In this module, each new poc found by CapFuzz represents a new capability.
- **Bug Capability Scaning**: to summurize all capabilities found by CapFuzz.
- **Severity Score**: to calculate severity score of the bug from bug capabilities.

You can use these modules either sequentially or seperately.

We also present CapSan based on AddressSanitizer to detect bug capabilities.

More details about the project can be found at the [paper](https://hexhive.epfl.ch/publications/files/22CCS.pdf). Our presentation about Evocatio can be found at the [slide](https://hexhive.epfl.ch/publications/files/22CCS-presentation.pdf).

## Requirement

We recommend cmake 3.22.0 and later version. We also provide `env_init.sh` and `instrument.sh`.  
`env_init.sh` can prepare necessary softwares for you.  
`instrument.sh` can compile your target with our tools.

## Components

This repository is structured as follows:

- lib (CapSan)
- bug-severity-AFLplusplus (POC Minimization, Critical Bytes Inference, CapFuzz)
- scripts (Bug Capability Scaning, SeverityScore)

We developed *lib* based on AddressSanitizer , and *bug-severity-AFLplusplus* based on AFLplusplus.

## Building

**Note: <project_path> stands for the directory of your project.**

- Starting from a new clean environment(e.g. a container), we recommend update necessary softwares using our bash:

    ```bash
    sh env_init.sh
    ```

- And then prepare cmake, here is one possible way(in UBUNTU for instance):

    ```bash
    apt-get install cmake
    ```

- To set CapSan up, please try:

    ```bash
    cp /<project_path>/lib/asan/afl/asan_afl_new.c /<project_path>/lib/asan/afl/asan_afl.c
    cd /<project_path>/lib/build
    cmake ..
    make
    ```

    (Under `/<project_path>/lib/asan/afl/`, there are `asan_afl_new.c` and `asan_afl_ori.c`. Please make sure you use the correct one. For more details, check usage example below.)

- To set CapFuzz up, please try:

    ```bash
    cd /<project_path>/bug-severity-AFLplusplus/
    make source-only NO_SPLICING=1
    ```

## Usage Example

**Note: <project_path> stands for the directory of your project.**

In this section, you can follow the steps to start from a clean container(e.g. UBUNTU 18.04):

1. Prepare necessary system environment and Evocatio referring to section *Building*.

2. Get your target program and POC.

3. Revise target C file, insert following codes in the end of the file:

    ```C
    #include "sanitizer/asan_interface.h"
    #include "my_asan_on_error.h"
    void __asan_on_error() {
        __my_asan_on_error();
    }
    ```

4. If needed, revise `instrument.sh` before you use it to compile target program.

5. Compile target program:

    ```bash
    sh /<project_path>/instrument.sh
    ```

6. Evocatio Function Module 1: POC Minimization (with `asan_afl_new.c`)

    ```bash
    ./<project_path>/bug-severity-AFLplusplus/afl-tmin-lazy -m none -i /path/to/original/poc -o /path/to/minimized/poc -- /path/to/target/program @@
    ```

    "@@" is a placeholder like in AFL++. If there are any commands surrounding "@@", keep them.

7. Evocatio Function Module 2: Critical Bytes Inference (with `asan_afl_new.c`)

    ```bash
    mkdir /<project_path>/seeds
    AFL_TMIN_EXACT=1 /<project_path>/bug-severity-AFLplusplus/cd-bytes-identifier -m none -i /path/to/poc -o /tmp/foo -g -c /tmp/constraints.res -k /<project_path>/seeds/ -- /path/to/target/program @@
    ```

    The output will be in `/<project_path>/seeds/`. If you'd like to use another fuzzer later, you may use seeds in `/<project_path>/seeds/` as your fuzzer's original seeds.

8. Evocatio Function Module 3: CapFuzz (with `asan_afl_ori.c`)

    Recompile CapSan and target program:

    ```bash
    cp /<project_path>/lib/asan/afl/asan_afl_ori.c /<project_path>/lib/asan/afl/asan_afl.c
    cd /<project_path>/lib/build
    cmake ..
    make
    sh /<project_path>/instrument.sh
    ```

    Start CapFuzz:

    ```bash
    ./<project_path>/bug-severity-AFLplusplus/afl-fuzz -m none -C -i /path/to/input/seeds/ -o /path/to/output/ -k /path/to/original/poc -- /path/to/target/program @@
    ```

9. Evocatio Function Module 4: Bug Capability Scaning (with `asan_afl_new.c`)

    Recompile CapSan and target program:

    ```bash
    cp /<project_path>/lib/asan/afl/asan_afl_new.c /<project_path>/lib/asan/afl/asan_afl.c
    cd /<project_path>/lib/build
    cmake ..
    make
    sh /<project_path>/instrument.sh
    ```

    Scan capabilities of poc:

    ```bash
    python3 /<project_path>/scripts/gen_raw_data_for_cve.py -i /path/to/new/crashes -o /path/to/bug/capability/json -b /path/to/target/program -a /path/to/commmands/file
    ```

    -i argument receives path to new pocs found by CapFuzz;  
    -o argument determines the output path of bug capability json file;  
    -b argument receives path to the target program(binary);  
    -a argument receives path to commands file(which means you should write commands surrounding "@@" to a file first).

10. Evocatio Function Module 5: Severity Score (with `asan_afl_new.c`)

    ```bash
    python3 /<project_path>/scripts/calculate_severity_score.py -i /path/to/bug/capability/json
    ```

    This will calulate bug severity score from bug capability json file. The severity score consists of reading score and writing score.

For detailed example, please refer to README in each subdirectory.

**NOTE:Everytime switching to a different Evocatio Function Module, please make sure that you compile CapSan with correspoding `asan_afl_ori.c` or `asan_afl_new.c`, which is indicated in each module. And then recompile target program too.**

## Development

Evocatio provides users with a flexible framework that allows developers to flexibly adjust CapSan, CapFuzz and scoring system according to their own needs. For everyone who wants to contribute (and send pull requests), please read our [contributing guidelines](https://github.com/HexHive/Evocatio/blob/main/CONTRIBUTING.md) before you submit.

## Contact

Questions? Concerns? Feel free to ping me via [E-mail](supermolejzy@gmail.com).

For recent update and new features implementation, please ping Mao who is pushing this project forward via [E-mail](maolc93@126.com).

## Cite

If you use Evocatio in scientific work, consider citing our [paper](https://doi.org/10.1145/3548606.3560575) presented at ACM CCS.

<details>

<summary>BibTeX</summary>

```bibtex
@inproceedings{10.1145/3548606.3560575,
author = {Jiang, Zhiyuan and Gan, Shuitao and Herrera, Adrian and Toffalini, Flavio and Romerio, Lucio and Tang, Chaojing and Egele, Manuel and Zhang, Chao and Payer, Mathias},
title = {Evocatio: Conjuring Bug Capabilities from a Single PoC},
year = {2022},
isbn = {9781450394505},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3548606.3560575},
doi = {10.1145/3548606.3560575},
booktitle = {Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security},
pages = {1599–1613},
numpages = {15},
keywords = {bug triaging, fuzzing, bug capability},
location = {Los Angeles, CA, USA},
series = {CCS '22}
}
```
</details>
