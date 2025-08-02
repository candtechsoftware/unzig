const std = @import("std");
const mem = std.mem;

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

pub const BitReader = struct {
    data: []const u8,
    byte_pos: usize = 0,
    bit_pos: u3 = 0,

    pub fn init(data: []const u8) BitReader {
        return .{ .data = data };
    }

    pub fn readBits(self: *BitReader, count: u5) !u32 {
        var result: u32 = 0;
        var bits_read: u5 = 0;

        while (bits_read < count) {
            if (self.byte_pos >= self.data.len) {
                return GzipError.UnexpectedEOF;
            }

            const bits_available = @as(u5, 8) - self.bit_pos;
            const bits_to_read = @min(bits_available, count - bits_read);
            const mask = (@as(u32, 1) << bits_to_read) - 1;

            const bits = (self.data[self.byte_pos] >> self.bit_pos) & @as(u8, @intCast(mask));
            result |= @as(u32, bits) << bits_read;

            bits_read += bits_to_read;
            const new_bit_pos = @as(u8, self.bit_pos) + bits_to_read;
            if (new_bit_pos >= 8) {
                self.bit_pos = @as(u3, @intCast(new_bit_pos - 8));
                self.byte_pos += 1;
            } else {
                self.bit_pos = @as(u3, @intCast(new_bit_pos));
            }
        }

        return result;
    }

    pub fn readBit(self: *BitReader) !bool {
        return (try self.readBits(1)) != 0;
    }

    pub fn alignToByte(self: *BitReader) void {
        if (self.bit_pos != 0) {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    pub fn readBytes(self: *BitReader, dest: []u8) !void {
        self.alignToByte();
        if (self.byte_pos + dest.len > self.data.len) {
            return GzipError.UnexpectedEOF;
        }
        @memcpy(dest, self.data[self.byte_pos..][0..dest.len]);
        self.byte_pos += dest.len;
    }

    pub fn readU16Le(self: *BitReader) !u16 {
        self.alignToByte();
        if (self.byte_pos + 2 > self.data.len) {
            return GzipError.UnexpectedEOF;
        }
        const result = mem.readInt(u16, self.data[self.byte_pos..][0..2], .little);
        self.byte_pos += 2;
        return result;
    }

    pub fn readU32Le(self: *BitReader) !u32 {
        self.alignToByte();
        if (self.byte_pos + 4 > self.data.len) {
            return GzipError.UnexpectedEOF;
        }
        const result = mem.readInt(u32, self.data[self.byte_pos..][0..4], .little);
        self.byte_pos += 4;
        return result;
    }
};

pub const HuffmanDecoder = struct {
    codes: []u16,      
    lens: []u8,        
    symbols: []u16,    
    count: u16,        

    pub fn init(allocator: mem.Allocator, code_lens: []const u8) !HuffmanDecoder {
        var count: u16 = 0;
        for (code_lens) |len| {
            if (len > 0) {
                count += 1;
                if (len > 15) return GzipError.InvalidHuffmanCode;
            }
        }

        if (count == 0) return GzipError.InvalidHuffmanCode;

        var codes = try allocator.alloc(u16, count);
        errdefer allocator.free(codes);
        var lens = try allocator.alloc(u8, count);
        errdefer allocator.free(lens);
        var symbols = try allocator.alloc(u16, count);
        errdefer allocator.free(symbols);

        var idx: u16 = 0;
        for (code_lens, 0..) |len, symbol| {
            if (len > 0) {
                lens[idx] = len;
                symbols[idx] = @intCast(symbol);
                idx += 1;
            }
        }

        var i: usize = 0;
        while (i < count - 1) : (i += 1) {
            var j: usize = i + 1;
            while (j < count) : (j += 1) {
                const swap = (lens[i] > lens[j]) or (lens[i] == lens[j] and symbols[i] > symbols[j]);
                if (swap) {
                    mem.swap(u8, &lens[i], &lens[j]);
                    mem.swap(u16, &symbols[i], &symbols[j]);
                }
            }
        }

        var bl_count = [_]u16{0} ** 16;
        for (0..count) |k| {
            bl_count[lens[k]] += 1;
        }

        var code: u16 = 0;
        var next_code = [_]u16{0} ** 16;
        for (1..16) |bits| {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        for (0..count) |k| {
            const len = lens[k];
            if (len > 0) {
                codes[k] = next_code[len];
                next_code[len] += 1;
            }
        }

        return HuffmanDecoder{
            .codes = codes,
            .lens = lens,
            .symbols = symbols,
            .count = count,
        };
    }

    pub fn decode(self: *const HuffmanDecoder, reader: *BitReader) !u16 {
        var code: u16 = 0;
        var bits: u8 = 0;

        while (bits <= 15) {
            bits += 1;
            const next_bit = try reader.readBits(1);
            code = (code << 1) | @as(u16, @intCast(next_bit));

            for (0..self.count) |i| {
                if (self.lens[i] == bits and self.codes[i] == code) {
                    return self.symbols[i];
                }
            }
        }

        return GzipError.InvalidHuffmanCode;
    }

    pub fn deinit(self: *const HuffmanDecoder, allocator: mem.Allocator) void {
        allocator.free(self.codes);
        allocator.free(self.lens);
        allocator.free(self.symbols);
    }
};

pub fn simdReadBits(reader: *BitReader, bits_array: []u5, results: []u32) !void {
    if (bits_array.len != results.len) return GzipError.InvalidBlock;
    
    const Vec8 = @Vector(8, u32);
    var i: usize = 0;
    
    while (i + 8 <= bits_array.len) : (i += 8) {
        var result_vec: Vec8 = @splat(0);
        
        for (0..8) |j| {
            result_vec[j] = try reader.readBits(bits_array[i + j]);
        }
        
        for (0..8) |j| {
            results[i + j] = result_vec[j];
        }
    }
    
    while (i < bits_array.len) : (i += 1) {
        results[i] = try reader.readBits(bits_array[i]);
    }
}

pub fn decompressFixedBlock(allocator: std.mem.Allocator, compressed_data: []const u8, uncompressed_size: usize) ![]u8 {
    _ = uncompressed_size;
    const root = @import("root.zig");
    return root.decompressDeflateData(allocator, compressed_data);
}