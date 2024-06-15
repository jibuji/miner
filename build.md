
### NOTICE

Before you build miner, you should build [pow](https://github.com/bitbi-core/pow) first.

Suppose your clone `pow` project is here: `/path-to-pow`, you should substitude it to your actual directory of `pow` project when following this document.

### build-msys2

#### prepare

install msys2 and open MSYS2-MINGW64 terminal

#### install dependencies

```bash
 pacman -S mingw-w64-x86_64-curl mingw-w64-x86_64-toolchain
```

#### build

```bash
./autogen.sh
./configure CPPFLAGS=" -I/path-to-pow/src" LIBS="-L/path-to-pow/build -lrandomx"
make
```

#### NOTICE

The result .exe file only can run in MSYS2-MINGW64 terminal. If you want to run it in Windows, you should copy these dll files (maybe not need all of them) to the same directory of the .exe file:

```bash

edit.dll             libiconv-2.dll     libsodium-26.dll     tcl86.dll
libbrotlicommon.dll  libidn2-0.dll      libssh2-1.dll        tk86.dll
libbrotlidec.dll     libintl-8.dll      libssl-3-x64.dll     vulkan-1.dll
libbrotlienc.dll     libjansson-4.dll   libstdc++-6.dll      zlib1.dll
libcrypto-3-x64.dll  libLerc.dll        libunistring-5.dll
libcurl-4.dll        libnghttp2-14.dll  libwinpthread-1.dll
libgcc_s_seh-1.dll   libpsl-5.dll       libzstd.dll

```

### build-ubuntu

### install dependencies

```bash
sudo apt update
sudo apt install -y libcurl4-openssl-dev
./autogen.sh
./nomacro.pl
./configure CPPFLAGS=" -I/path-to-pow/src" LIBS="-L/path-to-pow/build -lrandomx"
make
```
