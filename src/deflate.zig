const std = @import("std");
const BitReader = @import("BitReader.zig");

const log = std.log.scoped(.deflate);

pub fn decompressDeflate(allocator: std.mem.Allocator, compressed_data: []const u8, uncompressed_size: usize) ![]u8 {
    log.debug("Decompressing DEFLATE: {d} -> {d} bytes", .{ compressed_data.len, uncompressed_size });
    return BitReader.decompressFixedBlock(allocator, compressed_data, uncompressed_size);
}