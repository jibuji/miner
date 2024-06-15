#!/bin/sh

# You need autoconf 2.5x, preferably 2.57 or later
# You need automake 1.7 or later. 1.6 might work.

set -e

aclocal
autoheader
automake --gnu --add-missing --copy
autoconf

# /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang -o conftest -g -O2 -I/home/buji/code/RandomX/src -I/home/buji/code/bitbi/miner/depends/curl/include -I${NDK_PATH}/sysroot/usr/include conftest.c -lcurl -L/home/buji/code/RandomX/build -lrandomx -L/home/buji/code/bitbi/miner/depends/curl/lib/.libs -L${NDK_PATH}/platforms/android-28/arch-arm64/usr/lib -lcurl -lz