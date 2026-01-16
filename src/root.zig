const std = @import("std");

const regex = @import("regex.zig");

pub const Regex = regex.Regex;
pub const Match = regex.Match;
pub const RegexError = regex.RegexError;
pub const isRegexPattern = regex.isRegexPattern;

// Export internal types for GPU compiler
pub const State = regex.State;
pub const StateType = regex.StateType;

// Re-export SIMD utilities for use by other modules
pub const simd = @import("simd.zig");

test {
    std.testing.refAllDecls(@This());
    _ = @import("regex.zig");
    _ = @import("simd.zig");
}
