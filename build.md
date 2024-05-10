
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
