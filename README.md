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

## Components

This repository is structured as follows:

- bug-severity-AFLplusplus (POC Minimization, Critical Bytes Inference, CapFuzz, CapSan)
- scripts (Bug Capability Scaning, SeverityScore)

We developed *bug-severity-AFLplusplus* based on [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus). What's more, our *CapSan* was developed by leveraging the convenience of [`__asan_*` public interface](https://github.com/llvm/llvm-project/blob/b5c862e15caf4d8aa34bbc6ee25af8da9a9405a4/compiler-rt/include/sanitizer/asan_interface.h#L263) provided by [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer).

## Dependencies

### For *scripts*

Need *Python 3.x*. (Just Python's standard library is enough.)

### For *bug-severity-AFLplusplus*

Generally, requirement of *bug-severity-AFLplusplus* is just same as [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus).

However, you should pay more attention to the availability of *asan_interface.h*. AddressSanitizer is implemented by your compiler suite (such as *gcc* and *clang*), [which works by](https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm) instrumenting during the compilation phase and linking its run-time library into the final binary. *`__asan_*` public interface* is provided by its run-time library and declared in *asan_interface.h*. So make sure that your compiler suite provides this header.

## Building

The two python scripts in `./scripts` is out-of-the-box. Just build *bug-severity-AFLplusplus* like what is needed for *afl++*:

```bash
cd ./bug-severity-AFLplusplus
make source-only NO_SPLICING=1
```

:warning: Warning:

 - Ensure that `NO_SPLICING=1` is always used there.

 - Never use `ASAN_BUILD=1`. Otherwise our *bug-severity run-time dependency* may confuse your compiler and linker, as well as AddressSanitizer.

 - Since *afl++ 3.0* there is only one compiler *afl-cc* works for instrumenting your target, all previous compilers now symlink to it. We have hacked it so that our *bug-severity run-time dependency* can be linked into the target binary. If *afl-cc* couldn't be built and work properly, then all is over.

## Usage Example

For a quick start with *Evocatio*, you can follow these steps to start from scratch:

1. Download *Evocatio* into your system. Install dependencies and build Evocatio.

2. Get your target program and POC.

3. Compile and instrument your target program with *AddressSanitizer* enabled just as same as when using *afl++*.

   :warning: Ensure that *AddressSanitizer* is applied for your target. It is strongly recommended that set the environment variable `AFL_USE_ASAN=1` to tell  *afl-cc* do everything for you. Manually using compiler flag `-fsanitize=address` as [the doc says](https://github.com/google/sanitizers/wiki/AddressSanitizer) is also an alternative. 

4. **Evocatio Function Module** :one: : **POC Minimization**

    ```bash
    ./bug-severity-AFLplusplus/afl-tmin-lazy -m none -i /path/to/original/poc -o /path/to/minimized/poc -- /path/to/target/program @@
    ```

    "@@" is a placeholder like in AFL++. If there are any commands surrounding "@@", keep them.

5. **Evocatio Function Module** :two: : **Critical Bytes Inference**

    ```bash
    mkdir <your_path>/seeds
    ./bug-severity-AFLplusplus/cd-bytes-identifier -m none -i /path/to/poc -o /tmp/foo -g -c /tmp/constraints.res -k <your_path>/seeds -- /path/to/target/program @@
    ```

    The output will be in `<your_path>/seeds/`. If you'd like to use another fuzzer later, you may use seeds in `<your_path>/seeds/` as your fuzzer's original seeds.

6. **Evocatio Function Module** :three: : **CapFuzz**

    Start CapFuzz:

    ```bash
    ./bug-severity-AFLplusplus/afl-fuzz -m none -C -i /path/to/input/seeds/ -o /path/to/output/ -k /path/to/original/poc -- /path/to/target/program @@
    ```

7. **Evocatio Function Module** :four: : **Bug Capability Scaning**

    Scan capabilities of poc:

    ```bash
    python3 ./scripts/gen_raw_data_for_cve.py -i /path/to/new/crashes -o /path/to/bug/capability/json -b /path/to/target/program -a /path/to/commmands/file
    ```

    -i argument receives path to new pocs found by CapFuzz;  
    -o argument determines the output path of bug capability json file;  
    -b argument receives path to the target program(binary);  
    -a argument receives path to commands file(which means you should write commands surrounding "@@" to a file first).

8.  **Evocatio Function Module** :five: : **Severity Score**

    ```bash
    python3 ./scripts/calculate_severity_score.py -i /path/to/bug/capability/json
    ```

    This will calulate bug severity score from bug capability json file. The severity score consists of reading score and writing score.

For detailed example, please refer to README in each subdirectory.

## Development

Evocatio provides users with a flexible framework that allows developers to flexibly adjust CapSan, CapFuzz and scoring system according to their own needs. For everyone who wants to contribute (and send pull requests), please read our [contributing guidelines](https://github.com/HexHive/Evocatio/blob/main/CONTRIBUTING.md) before you submit.

## Contact

Questions? Concerns? Feel free to ping me via [E-mail](supermolejzy@gmail.com) for general questions and academic discussion.

For recent update and new features implementation：
- CapSan related issue/usage/feature: ping Sonic via [E-mail](observer000@qq.com)
- Next generation of Evocatio: ping Zhao via [E-mail](zhaowei_1999@qq.com)
- Installation, environment or other Evocatio questions: ping Mao via [E-mail](maolc93@126.com).

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
