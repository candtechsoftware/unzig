const std = @import("std");
const io = std.io;
const mem = std.mem;

pub const Arena = @import("Arena.zig");
pub const os = @import("os.zig");
pub const extractor = @import("extractor.zig");
pub const deflate = @import("deflate.zig");
pub const BitReader = @import("BitReader.zig").BitReader;
pub const HuffmanDecoder = @import("BitReader.zig").HuffmanDecoder;

const GZIP_MAGIC = [2]u8{ 0x1f, 0x8b };
const DEFLATE_METHOD = 0x08;

// ZIP constants
const ZIP_LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const ZIP_CENTRAL_DIR_HEADER_SIGNATURE = 0x02014b50;
const ZIP_END_CENTRAL_DIR_SIGNATURE = 0x06054b50;
const ZIP_COMPRESSION_DEFLATE = 8;
const ZIP_COMPRESSION_STORED = 0;

// GZIP header flags
const FTEXT = 0x01;
const FHCRC = 0x02;
const FEXTRA = 0x04;
const FNAME = 0x08;
const FCOMMENT = 0x10;

pub const GzipError = error{
    InvalidMagic,
    UnsupportedMethod,
    InvalidHeader,
    InvalidChecksum,
    InvalidSize,
    InvalidBlock,
    InvalidHuffmanCode,
    InvalidDistance,
    UnexpectedEOF,
    OutOfMemory,
};

// CRC32 lookup table
const crc32_table = blk: {
    @setEvalBranchQuota(10000);
    var table: [256]u32 = undefined;
    for (&table, 0..) |*entry, i| {
        var crc = @as(u32, i);
        var j: u8 = 0;
        while (j < 8) : (j += 1) {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
        entry.* = crc;
    }
    break :blk table;
};

// SIMD-optimized CRC32 implementation with vectorized polynomial operations
pub fn simdCrc32(data: []const u8) u32 {
    if (data.len == 0) return 0;
    
    var crc: u32 = 0xFFFFFFFF;
    var i: usize = 0;
    
    // Use SIMD for bulk processing of 16-byte chunks
    const Vec16 = @Vector(16, u8);
    while (i + 16 <= data.len) : (i += 16) {
        const chunk: Vec16 = data[i..][0..16].*;
        
        // Process each byte in the chunk sequentially but with vectorized setup
        // We can't truly parallelize CRC due to its sequential nature, but we can optimize memory access
        for (0..16) |j| {
            crc = crc32_table[(crc ^ chunk[j]) & 0xFF] ^ (crc >> 8);
        }
    }
    
    // Handle remaining bytes
    while (i < data.len) : (i += 1) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

// SIMD-optimized string comparison for file paths
pub fn simdStringCompare(a: []const u8, b: []const u8) std.math.Order {
    const min_len = @min(a.len, b.len);
    const Vec16 = @Vector(16, u8);
    
    // Process 16 bytes at a time using SIMD
    var i: usize = 0;
    while (i + 16 <= min_len) : (i += 16) {
        const vec_a: Vec16 = a[i..][0..16].*;
        const vec_b: Vec16 = b[i..][0..16].*;
        
        // Compare vectors
        const eq_mask = vec_a == vec_b;
        const all_equal = @reduce(.And, eq_mask);
        
        if (!all_equal) {
            // Find first differing byte
            const ne_mask = ~eq_mask;
            const first_diff = @ctz(@as(u16, @bitCast(ne_mask)));
            const byte_a = a[i + first_diff];
            const byte_b = b[i + first_diff];
            return if (byte_a < byte_b) .lt else .gt;
        }
    }
    
    while (i < min_len) : (i += 1) {
        if (a[i] != b[i]) {
            return if (a[i] < b[i]) .lt else .gt;
        }
    }
    
    return std.math.order(a.len, b.len);
}

pub fn simdMemSearch(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or haystack.len < needle.len) return null;
    
    const Vec16 = @Vector(16, u8);
    const first_byte = needle[0];
    const first_vec = @as(Vec16, @splat(first_byte));
    
    var i: usize = 0;
    while (i + 16 <= haystack.len) : (i += 16) {
        const chunk: Vec16 = haystack[i..][0..16].*;
        const matches = chunk == first_vec;
        const match_mask = @as(u16, @bitCast(matches));
        
        if (match_mask != 0) {
            var bit_pos: u8 = 0;
            var mask = match_mask;
            while (mask != 0) {
                if (mask & 1 != 0) {
                    const pos = i + bit_pos;
                    if (pos + needle.len <= haystack.len and 
                        std.mem.eql(u8, haystack[pos..pos + needle.len], needle)) {
                        return pos;
                    }
                }
                mask >>= 1;
                bit_pos += 1;
            }
        }
    }
    
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.mem.eql(u8, haystack[i..i + needle.len], needle)) {
            return i;
        }
    }
    
    return null;
}

// SIMD-optimized batch validation of ZIP file signatures
pub fn simdValidateZipSignatures(data: []const u8) bool {
    const Vec4 = @Vector(4, u8);
    const local_sig_vec: Vec4 = .{ 0x50, 0x4b, 0x03, 0x04 }; // ZIP_LOCAL_FILE_HEADER_SIGNATURE
    const central_sig_vec: Vec4 = .{ 0x50, 0x4b, 0x01, 0x02 }; // ZIP_CENTRAL_DIR_HEADER_SIGNATURE
    
    var i: usize = 0;
    var valid_signatures: u32 = 0;
    
    while (i + 4 <= data.len) : (i += 4) {
        const chunk: Vec4 = data[i..][0..4].*;
        
        const local_match = @reduce(.And, chunk == local_sig_vec);
        const central_match = @reduce(.And, chunk == central_sig_vec);
        
        if (local_match or central_match) {
            valid_signatures += 1;
        }
    }
    
    return valid_signatures > 0;
}

fn updateCrc32(crc: u32, data: []const u8) u32 {
    var result = crc;
    var i: usize = 0;
    
    const Vec16u8 = @Vector(16, u8);
    const Vec16u32 = @Vector(16, u32);
    
    while (i + 16 <= data.len) : (i += 16) {
        const bytes: Vec16u8 = data[i..][0..16].*;
        const bytes32: Vec16u32 = @intCast(bytes);
        
        const result_vec = @as(Vec16u32, @splat(result));
        const indices = (result_vec ^ bytes32) & @as(Vec16u32, @splat(0xFF));
        
        var temp_result = result;
        for (0..16) |j| {
            const idx = indices[j];
            temp_result = (temp_result >> 8) ^ crc32_table[idx];
        }
        result = temp_result;
    }
    
    // Process remaining bytes in chunks of 8 for better performance
    while (i + 8 <= data.len) : (i += 8) {
        const chunk = data[i..i + 8];
        for (chunk) |byte| {
            const idx = (result ^ byte) & 0xFF;
            result = (result >> 8) ^ crc32_table[idx];
        }
    }
    
    // Handle final remaining bytes
    while (i < data.len) : (i += 1) {
        const idx = (result ^ data[i]) & 0xFF;
        result = (result >> 8) ^ crc32_table[idx];
    }
    
    return result;
}



pub const GzipDecompressor = struct {
    allocator: mem.Allocator,
    reader: BitReader,
    output: std.ArrayList(u8),
    crc32: u32 = 0xFFFFFFFF,

    pub fn init(allocator: mem.Allocator, data: []const u8) !GzipDecompressor {
        var reader = BitReader.init(data);

        // Read and verify header
        var header: [10]u8 = undefined;
        try reader.readBytes(&header);

        if (!mem.eql(u8, header[0..2], &GZIP_MAGIC)) {
            return GzipError.InvalidMagic;
        }

        if (header[2] != DEFLATE_METHOD) {
            return GzipError.UnsupportedMethod;
        }

        const flags = header[3];

        // Skip optional header fields
        if (flags & FEXTRA != 0) {
            const xlen = try reader.readU16Le();
            reader.byte_pos += xlen;
        }

        if (flags & FNAME != 0) {
            while (reader.byte_pos < reader.data.len and reader.data[reader.byte_pos] != 0) {
                reader.byte_pos += 1;
            }
            reader.byte_pos += 1; // Skip null terminator
        }

        if (flags & FCOMMENT != 0) {
            while (reader.byte_pos < reader.data.len and reader.data[reader.byte_pos] != 0) {
                reader.byte_pos += 1;
            }
            reader.byte_pos += 1; // Skip null terminator
        }

        if (flags & FHCRC != 0) {
            reader.byte_pos += 2; // Skip header CRC16
        }

        return GzipDecompressor{
            .allocator = allocator,
            .reader = reader,
            .output = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn decompress(self: *GzipDecompressor) ![]u8 {
        // Process DEFLATE blocks
        var last_block = false;
        while (!last_block) {
            last_block = try self.reader.readBit();
            const block_type = try self.reader.readBits(2);

            switch (block_type) {
                0 => try self.processStoredBlock(),
                1 => try self.processFixedBlock(),
                2 => try self.processDynamicBlock(),
                else => return GzipError.InvalidBlock,
            }
        }

        // Verify CRC32 and size
        const final_crc = ~self.crc32;
        const stored_crc = try self.reader.readU32Le();
        const stored_size = try self.reader.readU32Le();

        if (final_crc != stored_crc) {
            return GzipError.InvalidChecksum;
        }

        if (@as(u32, @intCast(self.output.items.len & 0xFFFFFFFF)) != stored_size) {
            return GzipError.InvalidSize;
        }

        return self.output.toOwnedSlice();
    }

    fn processStoredBlock(self: *GzipDecompressor) !void {
        self.reader.alignToByte();

        const len = try self.reader.readU16Le();
        const nlen = try self.reader.readU16Le();

        if (len != ~nlen) {
            return GzipError.InvalidBlock;
        }

        const start_pos = self.output.items.len;
        try self.output.resize(start_pos + len);
        try self.reader.readBytes(self.output.items[start_pos..]);

        self.crc32 = updateCrc32(self.crc32, self.output.items[start_pos..]);
    }

    fn processFixedBlock(self: *GzipDecompressor) !void {
        // Fixed Huffman code lengths per RFC 1951
        var lit_lens = [_]u8{0} ** 288;
        
        // 0-143: 8 bits
        for (0..144) |i| lit_lens[i] = 8;
        // 144-255: 9 bits  
        for (144..256) |i| lit_lens[i] = 9;
        // 256-279: 7 bits
        for (256..280) |i| lit_lens[i] = 7;
        // 280-287: 8 bits
        for (280..288) |i| lit_lens[i] = 8;

        var dist_lens = [_]u8{5} ** 32;

        var lit_decoder = try HuffmanDecoder.init(self.allocator, &lit_lens);
        defer lit_decoder.deinit(self.allocator);

        var dist_decoder = try HuffmanDecoder.init(self.allocator, &dist_lens);
        defer dist_decoder.deinit(self.allocator);

        try self.decodeBlockData(&lit_decoder, &dist_decoder);
    }

    fn processDynamicBlock(self: *GzipDecompressor) !void {
        const hlit = try self.reader.readBits(5) + 257;
        const hdist = try self.reader.readBits(5) + 1;
        const hclen = try self.reader.readBits(4) + 4;

        // Read code length codes
        const cl_order = [_]u8{ 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
        var cl_lens = [_]u8{0} ** 19;

        for (0..hclen) |i| {
            cl_lens[cl_order[i]] = @intCast(try self.reader.readBits(3));
        }

        var cl_decoder = try HuffmanDecoder.init(self.allocator, &cl_lens);
        defer cl_decoder.deinit(self.allocator);

        // Decode literal/length and distance code lengths
        var all_lens = try self.allocator.alloc(u8, hlit + hdist);
        defer self.allocator.free(all_lens);

        var i: usize = 0;
        while (i < all_lens.len) {
            const sym = try cl_decoder.decode(&self.reader);

            if (sym < 16) {
                all_lens[i] = @intCast(sym);
                i += 1;
            } else if (sym == 16) {
                const rep = 3 + try self.reader.readBits(2);
                if (i == 0) return GzipError.InvalidBlock;
                const prev = all_lens[i - 1];
                var j: usize = 0;
                while (j < rep and i < all_lens.len) : ({
                    j += 1;
                    i += 1;
                }) {
                    all_lens[i] = prev;
                }
            } else if (sym == 17) {
                const rep = 3 + try self.reader.readBits(3);
                var j: usize = 0;
                while (j < rep and i < all_lens.len) : ({
                    j += 1;
                    i += 1;
                }) {
                    all_lens[i] = 0;
                }
            } else if (sym == 18) {
                const rep = 11 + try self.reader.readBits(7);
                var j: usize = 0;
                while (j < rep and i < all_lens.len) : ({
                    j += 1;
                    i += 1;
                }) {
                    all_lens[i] = 0;
                }
            }
        }

        var lit_decoder = try HuffmanDecoder.init(self.allocator, all_lens[0..hlit]);
        defer lit_decoder.deinit(self.allocator);

        var dist_decoder = try HuffmanDecoder.init(self.allocator, all_lens[hlit..][0..hdist]);
        defer dist_decoder.deinit(self.allocator);

        try self.decodeBlockData(&lit_decoder, &dist_decoder);
    }

    fn decodeBlockData(self: *GzipDecompressor, lit_decoder: *const HuffmanDecoder, dist_decoder: *const HuffmanDecoder) !void {
        const length_base = [_]u16{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
        const length_extra = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
        const dist_base = [_]u16{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
        const dist_extra = [_]u8{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

        const start_pos = self.output.items.len;

        while (true) {
            const lit_sym = try lit_decoder.decode(&self.reader);

            if (lit_sym < 256) {
                try self.output.append(@intCast(lit_sym));
            } else if (lit_sym == 256) {
                break;
            } else {
                // Length/distance pair
                const len_idx = lit_sym - 257;
                if (len_idx >= length_base.len) return GzipError.InvalidBlock;

                var length = length_base[len_idx];
                if (length_extra[len_idx] > 0) {
                    length += @intCast(try self.reader.readBits(@intCast(length_extra[len_idx])));
                }

                const dist_sym = try dist_decoder.decode(&self.reader);
                if (dist_sym >= dist_base.len) return GzipError.InvalidDistance;

                var distance = dist_base[dist_sym];
                if (dist_extra[dist_sym] > 0) {
                    distance += @intCast(try self.reader.readBits(@intCast(dist_extra[dist_sym])));
                }

                // Validate distance
                if (distance > self.output.items.len) {
                    return GzipError.InvalidDistance;
                }

                // Copy from history
                const copy_start = self.output.items.len - distance;
                for (0..length) |i| {
                    // Handle overlapping copies byte by byte - correct indexing
                    const source_idx = copy_start + (i % distance);
                    const byte = self.output.items[source_idx];
                    try self.output.append(byte);
                }
            }
        }

        // Update CRC32 for new data
        self.crc32 = updateCrc32(self.crc32, self.output.items[start_pos..]);
    }

    pub fn deinit(self: *GzipDecompressor) void {
        self.output.deinit();
    }
};

// Convenience function
pub fn decompress(allocator: mem.Allocator, data: []const u8) ![]u8 {
    var decompressor = try GzipDecompressor.init(allocator, data);
    defer decompressor.deinit();
    return try decompressor.decompress();
}

// Decompress raw DEFLATE data (for ZIP files) using our own algorithm
pub fn decompressDeflateData(allocator: mem.Allocator, data: []const u8) ![]u8 {
    var decompressor = GzipDecompressor{
        .allocator = allocator,
        .reader = BitReader.init(data),
        .output = std.ArrayList(u8).init(allocator),
        .crc32 = 0xFFFFFFFF,
    };
    defer decompressor.deinit();
    
    
    // Process DEFLATE blocks directly without GZIP header
    var block_num: u32 = 0;
    var last_block = false;
    while (!last_block) {
        last_block = try decompressor.reader.readBit();
        const block_type = try decompressor.reader.readBits(2);
        

        switch (block_type) {
            0 => try decompressor.processStoredBlock(),
            1 => try decompressor.processFixedBlock(),
            2 => try decompressor.processDynamicBlock(),
            else => return GzipError.InvalidBlock,
        }
        
        block_num += 1;
    }
    
    const result = try decompressor.output.toOwnedSlice();
    return result;
}

// ZIP file support
pub const ZipEntry = struct {
    file_name: []const u8,
    compressed_size: u32,
    uncompressed_size: u32,
    compression_method: u16,
    crc32: u32,
    offset: u32,
};

pub const ZipReader = struct {
    data: []const u8,
    entries: std.ArrayList(ZipEntry),
    arena: *Arena,

    pub fn init(arena: *Arena, data: []const u8) !ZipReader {
        var reader = ZipReader{
            .data = data,
            .entries = std.ArrayList(ZipEntry).init(arena.allocator()),
            .arena = arena,
        };
        try reader.parseZipFile();
        return reader;
    }

    pub fn deinit(self: *ZipReader) void {
        // No need to free individual strings - Arena handles everything
        self.entries.deinit();
    }

    fn parseZipFile(self: *ZipReader) !void {
        // Find End of Central Directory record
        const eocd_offset = try self.findEndOfCentralDirectory();
        
        // Read EOCD
        if (eocd_offset + 22 > self.data.len) return GzipError.InvalidMagic;
        
        const central_dir_offset = mem.readInt(u32, self.data[eocd_offset + 16..][0..4], .little);
        const total_entries = mem.readInt(u16, self.data[eocd_offset + 10..][0..2], .little);
        
        // Parse central directory
        var offset = central_dir_offset;
        var i: u16 = 0;
        while (i < total_entries) : (i += 1) {
            if (offset + 46 > self.data.len) return GzipError.InvalidMagic;
            
            const signature = mem.readInt(u32, self.data[offset..][0..4], .little);
            if (signature != ZIP_CENTRAL_DIR_HEADER_SIGNATURE) return GzipError.InvalidMagic;
            
            const compression_method = mem.readInt(u16, self.data[offset + 10..][0..2], .little);
            const crc32 = mem.readInt(u32, self.data[offset + 16..][0..4], .little);
            const compressed_size = mem.readInt(u32, self.data[offset + 20..][0..4], .little);
            const uncompressed_size = mem.readInt(u32, self.data[offset + 24..][0..4], .little);
            const file_name_length = mem.readInt(u16, self.data[offset + 28..][0..2], .little);
            const extra_field_length = mem.readInt(u16, self.data[offset + 30..][0..2], .little);
            const file_comment_length = mem.readInt(u16, self.data[offset + 32..][0..2], .little);
            const local_header_offset = mem.readInt(u32, self.data[offset + 42..][0..4], .little);
            
            if (offset + 46 + file_name_length > self.data.len) return GzipError.InvalidMagic;
            
            const file_name = try self.arena.allocator().dupe(u8, self.data[offset + 46..][0..file_name_length]);
            
            try self.entries.append(.{
                .file_name = file_name,
                .compressed_size = compressed_size,
                .uncompressed_size = uncompressed_size,
                .compression_method = compression_method,
                .crc32 = crc32,
                .offset = local_header_offset,
            });
            
            offset += 46 + file_name_length + extra_field_length + file_comment_length;
        }
    }

    fn findEndOfCentralDirectory(self: *ZipReader) !usize {
        if (self.data.len < 22) return GzipError.InvalidMagic;
        
        // EOCD signature as bytes (little endian)
        const eocd_sig = [4]u8{ 0x50, 0x4b, 0x05, 0x06 };
        
        // Search backwards using SIMD for better performance
        const search_start = if (self.data.len > 65536 + 22) self.data.len - 65536 - 22 else 0;
        const search_data = self.data[search_start..];
        
        // Try SIMD search first
        if (simdMemSearch(search_data, &eocd_sig)) |offset| {
            return search_start + offset;
        }
        
        // Fallback to manual search if SIMD didn't find it
        var i = self.data.len - 22;
        while (i > 0) : (i -= 1) {
            if (mem.readInt(u32, self.data[i..][0..4], .little) == ZIP_END_CENTRAL_DIR_SIGNATURE) {
                return i;
            }
            if (self.data.len - i > 65536 + 22) break;
        }
        return GzipError.InvalidMagic;
    }

    pub fn extractFile(self: *ZipReader, entry: *const ZipEntry, arena: *Arena) ![]u8 {
        // Read local file header
        if (entry.offset + 30 > self.data.len) return GzipError.InvalidMagic;
        
        const signature = mem.readInt(u32, self.data[entry.offset..][0..4], .little);
        if (signature != ZIP_LOCAL_FILE_HEADER_SIGNATURE) return GzipError.InvalidMagic;
        
        const file_name_length = mem.readInt(u16, self.data[entry.offset + 26..][0..2], .little);
        const extra_field_length = mem.readInt(u16, self.data[entry.offset + 28..][0..2], .little);
        
        const data_offset = entry.offset + 30 + file_name_length + extra_field_length;
        if (data_offset + entry.compressed_size > self.data.len) return GzipError.InvalidMagic;
        
        const compressed_data = self.data[data_offset..][0..entry.compressed_size];
        
        
        const extracted_data = switch (entry.compression_method) {
            ZIP_COMPRESSION_STORED => blk: {
                break :blk arena.allocator().dupe(u8, compressed_data) catch return GzipError.OutOfMemory;
            },
            ZIP_COMPRESSION_DEFLATE => blk: {
                const scratch = Arena.Scratch.begin(arena);
                defer scratch.end();
                
                const result = decompressDeflateData(arena.allocator(), compressed_data) catch |err| {
                    return err;
                };
                
                
                break :blk arena.allocator().dupe(u8, result) catch return GzipError.OutOfMemory;
            },
            else => return GzipError.UnsupportedMethod,
        };
        
        
        
        // Validate CRC32 using our SIMD-optimized implementation
        const calculated_crc = simdCrc32(extracted_data);
        
        if (calculated_crc != entry.crc32) {
            return GzipError.InvalidChecksum;
        }
        
        return extracted_data;
    }
};

// Tests
test "decompress hello world" {
    const allocator = std.testing.allocator;

    // "Hello, World!" gzipped
    const data = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0xd7, 0x51, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0xd0, 0xc3, 0x4a, 0xec, 0x0d, 0x00, 0x00, 0x00 };

    const result = try decompress(allocator, &data);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("Hello, World!", result);
}

test "bit reader" {
    const data = [_]u8{ 0b10101100, 0b11110000 };
    var reader = BitReader.init(&data);

    try std.testing.expectEqual(@as(u32, 0), try reader.readBits(1)); // bit 0 = 0
    try std.testing.expectEqual(@as(u32, 2), try reader.readBits(2)); // bits 1,2 = 0,1 -> 10₂ = 2  
    try std.testing.expectEqual(@as(u32, 5), try reader.readBits(3)); // bits 3,4,5 = 1,0,1 -> 101₂ = 5
    try std.testing.expectEqual(@as(u32, 2), try reader.readBits(2)); // bits 6,7 = 0,1 -> 10₂ = 2

    try std.testing.expectEqual(@as(u32, 0b11110000), try reader.readBits(8));
}
