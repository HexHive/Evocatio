Contributing to Evocatio
============================

Evocatio provides users with a flexible framework that allows developers to
flexibly adjust *CapSan*, *CapFuzz* and *scoring system* according to their own needs.
For the simplicity of the code and the flexibility of development, we only kept
the necessary codes during the open source process, and modified or deleted some
codes that limited the versatility of Evocatio. We have summarized some possible
improvements to Evocatio in the future, and hope that more developers will join
us to promote the progress of Evocatio.

## More Sanitizer support
At present, *CapSan* is developed based on Address Sanitizer, and has good support for memory
destructive vulnerabilities, especially the types of vulnerabilities represented
by OOB. However, in addition to Asan, academia and industry have also provided us with
some other new Sanitizers, which can support more bug types. By modifying
*CapSan*, Evocatio can explore the capabilities for more bug types, which would be
a very valuable work.

Adding support for other Sanitizers in *CapSan* will be a very simple task. Users
only need to use the API provided by Sanitizer to obtain the capability
information they want to monitor
(https://github.com/HexHive/Evocatio/blob/main/lib/asan/afl/asan_afl.c#L153),
perform hash calculations on all capability information
(https://github.com/HexHive/Evocatio/blob/main/lib/asan/afl/asan_afl.c#L207),
and recompile *CapSan*. Since *CapSan* and *CapFuzz* are completely independent,
adding new Sanitizer support does not require modifying *CapFuzz*.

We think the follwing sanitizers worth being added to Evocatio:
- [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
  (UndefinedBehaviorSanitizer)
- [KASAN](https://www.kernel.org/doc/html/v4.12/dev-tools/kasan.html) (Kernel
  Address Sanitizer)
- [MemorySanitizer](https://github.com/google/sanitizers/wiki/MemorySanitizer)
  (detects use of uninitialized memory)


## More efficient CapFuzz

CapFuzz is developed based on AFLplusplus, and uses "whether new bug
capabilities are found" as the most important guiding information. How to design
a fuzzing strategy that is more suitable for capability exploration is a problem
that requires further research. The optimization of CapFuzz includes but is not
limited to: seed selection strategy, energy scheduling strategy, seed mutation
strategy, etc.

It is worth noting that, in order to facilitate further development in the
future, CapFuzz currently retains the relevant strategies in AFLplusplus as much
as possible, and only adds the code necessary to realize capability exploration,
so CapFuzz still has a large room for optimization. Although capability
exploration is different from traditional bug finding tools (coverage
improvement is not the main purpose of CapFuzz), some optimization strategies
for fuzz testing technology itself proposed by the academic community can also
be applied to CapFuzz in theory.

## Do not insert code into target program

Currently CapSan needs to insert
(https://github.com/HexHive/Evocatio/blob/main/lib/tiffcp.c#L1875) a small
amount of code into the target program to set Asan's callback function, but this
insertion can be avoided. Users can modify CapSan to set Asan's callback
function in a more elegant way to avoid code insertion into the target program.
