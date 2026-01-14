const std = @import("std");

/// SIMD vector types for optimal performance
pub const Vec16 = @Vector(16, u8);
pub const Vec32 = @Vector(32, u8);
pub const Vec64 = @Vector(64, u8);
pub const BoolVec16 = @Vector(16, bool);
pub const BoolVec32 = @Vector(32, bool);
pub const BoolVec64 = @Vector(64, bool);

/// Pre-computed character class vectors
pub const CharClass = struct {
    /// Bitmap for ASCII characters (256 bits = 32 bytes = 4x Vec64 or 2x Vec128)
    bitmap: [32]u8,

    pub fn init() CharClass {
        return .{ .bitmap = std.mem.zeroes([32]u8) };
    }

    /// Add a single character to the class
    pub inline fn addChar(self: *CharClass, c: u8) void {
        self.bitmap[c >> 3] |= @as(u8, 1) << @intCast(c & 7);
    }

    /// Add a range of characters [start, end] inclusive
    pub fn addRange(self: *CharClass, start: u8, end: u8) void {
        var c = start;
        while (c <= end) : (c += 1) {
            self.addChar(c);
            if (c == 255) break;
        }
    }

    /// Check if character is in the class
    pub inline fn contains(self: *const CharClass, c: u8) bool {
        return (self.bitmap[c >> 3] & (@as(u8, 1) << @intCast(c & 7))) != 0;
    }

    /// Negate the character class
    pub fn negate(self: *CharClass) void {
        for (&self.bitmap) |*byte| {
            byte.* = ~byte.*;
        }
    }

    /// Pre-built character classes
    pub const digit = blk: {
        var cc = CharClass.init();
        cc.addRange('0', '9');
        break :blk cc;
    };

    pub const word = blk: {
        var cc = CharClass.init();
        cc.addRange('a', 'z');
        cc.addRange('A', 'Z');
        cc.addRange('0', '9');
        cc.addChar('_');
        break :blk cc;
    };

    pub const whitespace = blk: {
        var cc = CharClass.init();
        cc.addChar(' ');
        cc.addChar('\t');
        cc.addChar('\n');
        cc.addChar('\r');
        cc.addChar(0x0B); // vertical tab
        cc.addChar(0x0C); // form feed
        break :blk cc;
    };

    pub const not_digit = blk: {
        var cc = digit;
        cc.negate();
        break :blk cc;
    };

    pub const not_word = blk: {
        var cc = word;
        cc.negate();
        break :blk cc;
    };

    pub const not_whitespace = blk: {
        var cc = whitespace;
        cc.negate();
        break :blk cc;
    };
};

/// SIMD-accelerated character search in text
/// Returns index of first occurrence or null
pub fn findChar(text: []const u8, char: u8) ?usize {
    const target: Vec32 = @splat(char);
    var i: usize = 0;

    // Process 32 bytes at a time
    while (i + 32 <= text.len) {
        const chunk: Vec32 = text[i..][0..32].*;
        const matches = chunk == target;
        if (@reduce(.Or, matches)) {
            // Find exact position
            for (0..32) |j| {
                if (text[i + j] == char) return i + j;
            }
        }
        i += 32;
    }

    // Handle remaining bytes
    while (i < text.len) {
        if (text[i] == char) return i;
        i += 1;
    }

    return null;
}

/// SIMD-accelerated newline search
pub fn findNewline(text: []const u8, start: usize) ?usize {
    const newline: Vec32 = @splat('\n');
    var i = start;

    while (i + 32 <= text.len) {
        const chunk: Vec32 = text[i..][0..32].*;
        const matches = chunk == newline;
        if (@reduce(.Or, matches)) {
            for (0..32) |j| {
                if (text[i + j] == '\n') return i + j;
            }
        }
        i += 32;
    }

    while (i < text.len) {
        if (text[i] == '\n') return i;
        i += 1;
    }

    return null;
}

/// SIMD-accelerated character class matching
/// Returns true if any character in chunk matches the class
pub fn matchCharClassChunk(chunk: Vec32, class: *const CharClass) BoolVec32 {
    var result: BoolVec32 = @splat(false);
    for (0..32) |i| {
        result[i] = class.contains(chunk[i]);
    }
    return result;
}

/// Find first character matching a character class
pub fn findCharClass(text: []const u8, class: *const CharClass) ?usize {
    var i: usize = 0;

    // Process 32 bytes at a time
    while (i + 32 <= text.len) {
        const chunk: Vec32 = text[i..][0..32].*;
        const matches = matchCharClassChunk(chunk, class);
        if (@reduce(.Or, matches)) {
            for (0..32) |j| {
                if (class.contains(text[i + j])) return i + j;
            }
        }
        i += 32;
    }

    // Handle remaining bytes
    while (i < text.len) {
        if (class.contains(text[i])) return i;
        i += 1;
    }

    return null;
}

/// SIMD-accelerated case-insensitive character comparison
pub inline fn toLowerVec32(v: Vec32) Vec32 {
    const upper_a: Vec32 = @splat('A');
    const upper_z: Vec32 = @splat('Z');
    const case_diff: Vec32 = @splat(32);
    const is_upper = (v >= upper_a) & (v <= upper_z);
    return @select(u8, is_upper, v + case_diff, v);
}

pub inline fn toLowerVec16(v: Vec16) Vec16 {
    const upper_a: Vec16 = @splat('A');
    const upper_z: Vec16 = @splat('Z');
    const case_diff: Vec16 = @splat(32);
    const is_upper = (v >= upper_a) & (v <= upper_z);
    return @select(u8, is_upper, v + case_diff, v);
}

pub inline fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// SIMD-accelerated literal string search using Boyer-Moore-Horspool
pub fn searchLiteral(text: []const u8, pattern: []const u8, case_insensitive: bool) ?usize {
    if (pattern.len == 0) return 0;
    if (text.len < pattern.len) return null;

    // Build skip table
    var skip_table: [256]usize = undefined;
    @memset(&skip_table, pattern.len);

    for (0..pattern.len - 1) |i| {
        const c = if (case_insensitive) toLower(pattern[i]) else pattern[i];
        skip_table[c] = pattern.len - 1 - i;
        if (case_insensitive and c >= 'a' and c <= 'z') {
            skip_table[c - 32] = pattern.len - 1 - i;
        }
    }

    // Pre-compute lowercase pattern
    var lower_pattern: [1024]u8 = undefined;
    if (case_insensitive and pattern.len <= 1024) {
        for (0..pattern.len) |i| {
            lower_pattern[i] = toLower(pattern[i]);
        }
    }

    var pos: usize = 0;
    while (pos + pattern.len <= text.len) {
        // Compare using SIMD when possible
        const matched = if (case_insensitive)
            matchAtPositionSIMD(text, pos, lower_pattern[0..pattern.len], true)
        else
            matchAtPositionSIMD(text, pos, pattern, false);

        if (matched) return pos;

        const skip_char = if (case_insensitive)
            toLower(text[pos + pattern.len - 1])
        else
            text[pos + pattern.len - 1];
        const skip = skip_table[skip_char];
        pos += @max(skip, 1);
    }

    return null;
}

/// SIMD-optimized comparison at position
pub fn matchAtPositionSIMD(text: []const u8, pos: usize, pattern: []const u8, case_insensitive: bool) bool {
    if (pos + pattern.len > text.len) return false;

    const text_slice = text[pos..][0..pattern.len];
    var offset: usize = 0;

    // Process 32 bytes at a time
    while (offset + 32 <= pattern.len) {
        const text_vec: Vec32 = text_slice[offset..][0..32].*;
        const pattern_vec: Vec32 = pattern[offset..][0..32].*;

        const cmp_result = if (case_insensitive)
            toLowerVec32(text_vec) == pattern_vec
        else
            text_vec == pattern_vec;

        if (!@reduce(.And, cmp_result)) return false;
        offset += 32;
    }

    // Process 16 bytes at a time
    while (offset + 16 <= pattern.len) {
        const text_vec: Vec16 = text_slice[offset..][0..16].*;
        const pattern_vec: Vec16 = pattern[offset..][0..16].*;

        const cmp_result = if (case_insensitive)
            toLowerVec16(text_vec) == pattern_vec
        else
            text_vec == pattern_vec;

        if (!@reduce(.And, cmp_result)) return false;
        offset += 16;
    }

    // Handle remaining bytes
    while (offset < pattern.len) {
        var tc = text_slice[offset];
        const pc = pattern[offset];

        if (case_insensitive) {
            tc = toLower(tc);
        }

        if (tc != pc) return false;
        offset += 1;
    }

    return true;
}

/// Count occurrences of a character in text using SIMD
pub fn countChar(text: []const u8, char: u8) usize {
    const target: Vec32 = @splat(char);
    var count: usize = 0;
    var i: usize = 0;

    while (i + 32 <= text.len) {
        const chunk: Vec32 = text[i..][0..32].*;
        const matches = chunk == target;
        count += @popCount(@as(u32, @bitCast(matches)));
        i += 32;
    }

    while (i < text.len) {
        if (text[i] == char) count += 1;
        i += 1;
    }

    return count;
}

/// Check if character is a word character (alphanumeric + underscore)
pub inline fn isWordChar(c: u8) bool {
    return CharClass.word.contains(c);
}

/// Check word boundary at position
pub fn isWordBoundary(text: []const u8, pos: usize) bool {
    const before = if (pos > 0) isWordChar(text[pos - 1]) else false;
    const after = if (pos < text.len) isWordChar(text[pos]) else false;
    return before != after;
}

// Tests
test "CharClass basic operations" {
    var cc = CharClass.init();
    cc.addChar('a');
    cc.addRange('0', '9');

    try std.testing.expect(cc.contains('a'));
    try std.testing.expect(cc.contains('5'));
    try std.testing.expect(!cc.contains('b'));
}

test "CharClass prebuilt classes" {
    try std.testing.expect(CharClass.digit.contains('5'));
    try std.testing.expect(!CharClass.digit.contains('a'));

    try std.testing.expect(CharClass.word.contains('a'));
    try std.testing.expect(CharClass.word.contains('Z'));
    try std.testing.expect(CharClass.word.contains('_'));
    try std.testing.expect(!CharClass.word.contains(' '));

    try std.testing.expect(CharClass.whitespace.contains(' '));
    try std.testing.expect(CharClass.whitespace.contains('\n'));
    try std.testing.expect(!CharClass.whitespace.contains('a'));
}

test "findChar SIMD" {
    const text = "hello world, this is a test string for SIMD search";
    try std.testing.expectEqual(@as(?usize, 4), findChar(text, 'o'));
    try std.testing.expectEqual(@as(?usize, 0), findChar(text, 'h'));
    try std.testing.expectEqual(@as(?usize, null), findChar(text, 'z'));
}

test "searchLiteral" {
    const text = "hello world, this is a test";
    try std.testing.expectEqual(@as(?usize, 0), searchLiteral(text, "hello", false));
    try std.testing.expectEqual(@as(?usize, 6), searchLiteral(text, "world", false));
    try std.testing.expectEqual(@as(?usize, null), searchLiteral(text, "xyz", false));
}

test "searchLiteral case insensitive" {
    const text = "Hello World";
    try std.testing.expectEqual(@as(?usize, 0), searchLiteral(text, "hello", true));
    try std.testing.expectEqual(@as(?usize, 6), searchLiteral(text, "WORLD", true));
}

test "countChar" {
    const text = "hello world";
    try std.testing.expectEqual(@as(usize, 3), countChar(text, 'l'));
    try std.testing.expectEqual(@as(usize, 2), countChar(text, 'o'));
    try std.testing.expectEqual(@as(usize, 0), countChar(text, 'z'));
}

test "isWordBoundary" {
    const text = "hello world";
    try std.testing.expect(isWordBoundary(text, 0)); // start
    try std.testing.expect(isWordBoundary(text, 5)); // after 'hello'
    try std.testing.expect(isWordBoundary(text, 6)); // before 'world'
    try std.testing.expect(!isWordBoundary(text, 3)); // middle of 'hello'
}
