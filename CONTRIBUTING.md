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

Adding support for other Sanitizers in *CapSan* is easy. You can firstly use the public interfaces provided by the new Sanitizer to obtain and process the capability information you want to monitor (implemented in [bug-severity-rt.o.c](https://github.com/HexHive/Evocatio/blob/main/bug-severity-AFLplusplus/instrumentation/bug-severity-rt.o.c)), then hack [afl-cc.c](https://github.com/HexHive/Evocatio/blob/main/bug-severity-AFLplusplus/instrumentation/bug-severity-AFLplusplus/src/afl-cc.c) to link the run-time dependency at the time of the new Sanitizer being applied by your compiler suite.

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
