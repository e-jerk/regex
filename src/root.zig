const std = @import("std");

pub const Regex = @import("regex.zig").Regex;
pub const Match = @import("regex.zig").Match;
pub const RegexError = @import("regex.zig").RegexError;
pub const isRegexPattern = @import("regex.zig").isRegexPattern;

// Re-export SIMD utilities for use by other modules
pub const simd = @import("simd.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("regex.zig");
    _ = @import("simd.zig");
}
