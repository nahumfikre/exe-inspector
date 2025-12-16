# exe-inspector

A lightweight command-line tool for inspecting executable file formats. Supports PE (Windows), Mach-O (macOS/iOS), and FAT/Universal binaries.

## Features

- **Format Detection**: Automatically identifies PE, Mach-O, and FAT binary formats
- **Header Analysis**: Extracts key metadata from executable headers
- **Architecture Info**: Shows CPU type, file type, and characteristics
- **String Extraction**: Finds printable ASCII strings in binaries (with `--verbose`)
- **Multi-Architecture**: Inspects FAT/Universal binaries with multiple architectures

## Building

```bash
make
```

The binary will be compiled to `bin/exe_inspector`

## Usage

```bash
./bin/exe_inspector <file> [--verbose]
```

**Options:**
- `--verbose`: Enable detailed output including string extraction

## Examples

### Basic inspection
```bash
./bin/exe_inspector /bin/ls
```

Output:
```
file: /bin/ls
type: Mach-O 64 (little)
cputype: arm64 (0x100000c)
filetype: 2  (1=obj,2=exec,6=dylib,7=bundle)
ncmds: 19  sizeofcmds: 1336
flags: 0x218085
```

### Verbose mode with strings
```bash
./bin/exe_inspector /bin/ls --verbose
```

Additional output includes:
```
--- Strings (min length 4) ---
0x00003c20: usage: ls [options] [file ...]
0x00004d8a: /usr/lib/libSystem.B.dylib
...
```

## Supported Formats

### PE (Portable Executable)
- Windows .exe and .dll files
- Shows machine type, section count, timestamp, and characteristics

### Mach-O
- macOS and iOS executables, libraries, and bundles
- Both 32-bit and 64-bit variants
- Little and big endian support
- Shows CPU type (x86, x86_64, arm, arm64, ppc, ppc64)

### FAT/Universal Binaries
- Multi-architecture Mach-O containers
- Shows all contained architectures with offsets and sizes
- Supports both 32-bit and 64-bit FAT formats

## String Extraction

When run with `--verbose`, the tool scans the binary for printable ASCII sequences:
- Minimum length: 4 characters
- Shows hex offset where each string starts
- Useful for finding embedded text, error messages, library paths, and symbols

## Clean

```bash
make clean
```
