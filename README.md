# Unzig

Fast ZIP extraction tool written in Zig with SIMD-optimized DEFLATE decompression.

## Build

```bash
zig build -Doptimize=ReleaseFast
```

## Usage

```bash
# Extract ZIP file to directory
./zig-out/bin/unzip archive.zip output_directory
```

## Features

- Full DEFLATE decompression with Huffman encoding and LZ77 support
- SIMD-optimized string comparison and CRC32 validation
- Memory-efficient arena-based allocation

## Support 
| Platform | Supported |
|----------|-----------|
| Windows  | ✅        |
| macOS    | ❌ (Planned)|
| Linux    | ❌ (Planned)|
