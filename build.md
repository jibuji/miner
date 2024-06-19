
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


### build-android

### install latest ndk
    
```bash
wget https://dl.google.com/android/repository/android-ndk-r26d-linux-x86_64.zip
unzip android-ndk-r26d-linux-x86_64.zip
export ANDROID_NDK_HOME=/path-to-android-ndk-r26d
# in current project
mkdir depends
cd depends
# download latest curl and build using android ndk
wget https://curl.haxx.se/download/curl-7.64.1.tar.gz
tar -xvf curl-7.64.1.tar.gz
mv curl-7.64.1 curl
cd curl
mkdir build-android
cd build-android
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake -DANDROID_NDK=$ANDROID_NDK_HOME -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCURL_ENABLE_SSL=OFF ..
make

# in pow project
mkdir build-android
cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 ..
make

# in current project
export CROSS_COMPILE_FOR_NDK=yes
./autogen.sh
./configure CPPFLAGS=" -I/home/buji/code/bitbi/pow/src -I/home/buji/code/bitbi/miner/depends/curl/include" LIBS="-L/home/buji/code/bitbi/pow/build-android -lrandomx -lz -L/home/buji/code/bitbi/miner/depends/curl/build-android/lib -lcurl" --host=arm64-linux-androideab --disable-assembly

make

#when you run the miner in android, you should copy the minerd files to the android 
# device and one libc++_shared.so file which can be found in NDK, and export LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/data/local/tmp:$LD_LIBRARY_PATH


```
