# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/buji/code/bitbi/miner/depends/curl

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/buji/code/bitbi/miner/depends/curl/build-android

# Include any dependencies generated for this target.
include tests/libtest/CMakeFiles/libntlmconnect.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/libtest/CMakeFiles/libntlmconnect.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/libtest/CMakeFiles/libntlmconnect.dir/progress.make

# Include the compile flags for this target's objects.
include tests/libtest/CMakeFiles/libntlmconnect.dir/flags.make

tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o: tests/libtest/CMakeFiles/libntlmconnect.dir/flags.make
tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o: ../tests/libtest/libntlmconnect.c
tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o: tests/libtest/CMakeFiles/libntlmconnect.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/buji/code/bitbi/miner/depends/curl/build-android/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o -MF CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o.d -o CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o -c /home/buji/code/bitbi/miner/depends/curl/tests/libtest/libntlmconnect.c

tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/libntlmconnect.dir/libntlmconnect.c.i"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/buji/code/bitbi/miner/depends/curl/tests/libtest/libntlmconnect.c > CMakeFiles/libntlmconnect.dir/libntlmconnect.c.i

tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/libntlmconnect.dir/libntlmconnect.c.s"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/buji/code/bitbi/miner/depends/curl/tests/libtest/libntlmconnect.c -o CMakeFiles/libntlmconnect.dir/libntlmconnect.c.s

tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.o: tests/libtest/CMakeFiles/libntlmconnect.dir/flags.make
tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.o: ../tests/libtest/first.c
tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.o: tests/libtest/CMakeFiles/libntlmconnect.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/buji/code/bitbi/miner/depends/curl/build-android/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.o"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.o -MF CMakeFiles/libntlmconnect.dir/first.c.o.d -o CMakeFiles/libntlmconnect.dir/first.c.o -c /home/buji/code/bitbi/miner/depends/curl/tests/libtest/first.c

tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/libntlmconnect.dir/first.c.i"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/buji/code/bitbi/miner/depends/curl/tests/libtest/first.c > CMakeFiles/libntlmconnect.dir/first.c.i

tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/libntlmconnect.dir/first.c.s"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/buji/code/bitbi/miner/depends/curl/tests/libtest/first.c -o CMakeFiles/libntlmconnect.dir/first.c.s

tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.o: tests/libtest/CMakeFiles/libntlmconnect.dir/flags.make
tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.o: ../tests/libtest/testutil.c
tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.o: tests/libtest/CMakeFiles/libntlmconnect.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/buji/code/bitbi/miner/depends/curl/build-android/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.o"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.o -MF CMakeFiles/libntlmconnect.dir/testutil.c.o.d -o CMakeFiles/libntlmconnect.dir/testutil.c.o -c /home/buji/code/bitbi/miner/depends/curl/tests/libtest/testutil.c

tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/libntlmconnect.dir/testutil.c.i"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/buji/code/bitbi/miner/depends/curl/tests/libtest/testutil.c > CMakeFiles/libntlmconnect.dir/testutil.c.i

tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/libntlmconnect.dir/testutil.c.s"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-none-linux-android23 --sysroot=/home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/buji/code/bitbi/miner/depends/curl/tests/libtest/testutil.c -o CMakeFiles/libntlmconnect.dir/testutil.c.s

# Object files for target libntlmconnect
libntlmconnect_OBJECTS = \
"CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o" \
"CMakeFiles/libntlmconnect.dir/first.c.o" \
"CMakeFiles/libntlmconnect.dir/testutil.c.o"

# External object files for target libntlmconnect
libntlmconnect_EXTERNAL_OBJECTS =

tests/libtest/libntlmconnect: tests/libtest/CMakeFiles/libntlmconnect.dir/libntlmconnect.c.o
tests/libtest/libntlmconnect: tests/libtest/CMakeFiles/libntlmconnect.dir/first.c.o
tests/libtest/libntlmconnect: tests/libtest/CMakeFiles/libntlmconnect.dir/testutil.c.o
tests/libtest/libntlmconnect: tests/libtest/CMakeFiles/libntlmconnect.dir/build.make
tests/libtest/libntlmconnect: lib/libcurl.a
tests/libtest/libntlmconnect: /home/buji/Android/Sdk/ndk/27.0.11902837/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/23/libz.so
tests/libtest/libntlmconnect: tests/libtest/CMakeFiles/libntlmconnect.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/buji/code/bitbi/miner/depends/curl/build-android/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable libntlmconnect"
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/libntlmconnect.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/libtest/CMakeFiles/libntlmconnect.dir/build: tests/libtest/libntlmconnect
.PHONY : tests/libtest/CMakeFiles/libntlmconnect.dir/build

tests/libtest/CMakeFiles/libntlmconnect.dir/clean:
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest && $(CMAKE_COMMAND) -P CMakeFiles/libntlmconnect.dir/cmake_clean.cmake
.PHONY : tests/libtest/CMakeFiles/libntlmconnect.dir/clean

tests/libtest/CMakeFiles/libntlmconnect.dir/depend:
	cd /home/buji/code/bitbi/miner/depends/curl/build-android && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/buji/code/bitbi/miner/depends/curl /home/buji/code/bitbi/miner/depends/curl/tests/libtest /home/buji/code/bitbi/miner/depends/curl/build-android /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest /home/buji/code/bitbi/miner/depends/curl/build-android/tests/libtest/CMakeFiles/libntlmconnect.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/libtest/CMakeFiles/libntlmconnect.dir/depend

