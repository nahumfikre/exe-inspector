# Executable Inspector (C++)

Simple C++ tool that identifies executable file formats and prints basic header information. It can detect:
- Mach-O (macOS executables)
- FAT / Universal Mach-O (multi-architecture binaries like x86_64 + arm64)
- Windows PE files (.exe / .dll)

This is a minimal, readable version meant to be extended later (section parsing, SHA-256, JSON output, etc.).

---

## Build and Run

```bash
# go into the project folder
cd exe-inspector

# build the project (creates ./bin/exe_inspector)
make

# inspect a macOS binary
./bin/exe_inspector /bin/ls

# inspect clang
./bin/exe_inspector /usr/bin/clang

# verbose mode (extra debug info)
./bin/exe_inspector /bin/ls --verbose

# inspect a Windows .exe file (if you have one locally)
./bin/exe_inspector somefile.exe

# clean build files
make clean
