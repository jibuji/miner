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

# Utility rule file for test-full.

# Include any custom commands dependencies for this target.
include tests/CMakeFiles/test-full.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test-full.dir/progress.make

tests/CMakeFiles/test-full:
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests && /usr/bin/perl /home/buji/code/bitbi/miner/depends/curl/tests/runtests.pl -a -p -r "\$$TFLAGS"

test-full: tests/CMakeFiles/test-full
test-full: tests/CMakeFiles/test-full.dir/build.make
.PHONY : test-full

# Rule to build all files generated by this target.
tests/CMakeFiles/test-full.dir/build: test-full
.PHONY : tests/CMakeFiles/test-full.dir/build

tests/CMakeFiles/test-full.dir/clean:
	cd /home/buji/code/bitbi/miner/depends/curl/build-android/tests && $(CMAKE_COMMAND) -P CMakeFiles/test-full.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test-full.dir/clean

tests/CMakeFiles/test-full.dir/depend:
	cd /home/buji/code/bitbi/miner/depends/curl/build-android && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/buji/code/bitbi/miner/depends/curl /home/buji/code/bitbi/miner/depends/curl/tests /home/buji/code/bitbi/miner/depends/curl/build-android /home/buji/code/bitbi/miner/depends/curl/build-android/tests /home/buji/code/bitbi/miner/depends/curl/build-android/tests/CMakeFiles/test-full.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test-full.dir/depend

