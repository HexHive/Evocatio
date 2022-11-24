#!/bin/bash

set -e

# Set compilation env
# If your project is not in the /root , please revise accordingly
export CC="/root/bug-severity-AFLplusplus/afl-clang-fast"
export CXX="/root/bug-severity-AFLplusplus/afl-clang-fast++"
export CFLAGS="$CFLAGS -g -O0 -I /root/lib"
export CXXFLAGS="$CXXFLAGS -g -O0 -I /root/lib"
export LD="/root/bug-severity-AFLplusplus/afl-clang-fast"
export LIBS="$LIBS /root/lib/build/asan/afl/libasan_afl.a"
export AFL_USE_ASAN=1

# Build
# Please keep the configuration needed for conpiling target program
# cd "/path/to/target/program/"
# ./configure --disable-shared

# make -j$(nproc) clean
# make -v -j$(nproc)
# make install

