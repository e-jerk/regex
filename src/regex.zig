const std = @import("std");
const simd = @import("simd.zig");

/// Regex engine supporting POSIX Extended Regular Expressions (ERE)
/// Features: . * + ? | ^ $ () [] [^] {n,m} \d \w \s \b and backreferences
/// Optimized with SIMD for character class matching and literal prefixes

pub const RegexError = error{
    InvalidPattern,
    UnmatchedParen,
    UnmatchedBracket,
    InvalidQuantifier,
    InvalidEscape,
    InvalidRange,
    OutOfMemory,
    PatternTooComplex,
};

/// Match result with capture groups
pub const Match = struct {
    start: usize,
    end: usize,
    groups: []?Group,
    allocator: std.mem.Allocator,

    pub const Group = struct {
        start: usize,
        end: usize,
    };

    pub fn deinit(self: *Match) void {
        self.allocator.free(self.groups);
    }

    pub fn text(self: *const Match, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }

    pub fn group(self: *const Match, idx: usize, source: []const u8) ?[]const u8 {
        if (idx >= self.groups.len) return null;
        if (self.groups[idx]) |g| {
            return source[g.start..g.end];
        }
        return null;
    }
};

/// Compiled regex pattern
pub const Regex = struct {
    allocator: std.mem.Allocator,
    states: []State,
    start_state: u32,
    num_groups: usize,
    anchored_start: bool,
    anchored_end: bool,
    /// Literal prefix storage for fast filtering (SIMD-accelerated skip)
    literal_prefix_storage: [64]u8,
    literal_prefix_len: usize,
    case_insensitive: bool,
    multiline: bool,

    /// Get the literal prefix slice (points to struct's own storage)
    pub fn getLiteralPrefix(self: *const Regex) ?[]const u8 {
        if (self.literal_prefix_len > 0) {
            return self.literal_prefix_storage[0..self.literal_prefix_len];
        }
        return null;
    }

    pub fn compile(allocator: std.mem.Allocator, pattern: []const u8, options: Options) !Regex {
        var compiler = Compiler.init(allocator, pattern, options);
        return compiler.compile();
    }

    pub fn deinit(self: *Regex) void {
        for (self.states) |*state| {
            state.deinit(self.allocator);
        }
        self.allocator.free(self.states);
    }

    /// Check if the text matches the pattern anywhere
    pub fn isMatch(self: *const Regex, text: []const u8) bool {
        var m = self.find(text, self.allocator) catch return false;
        if (m) |*match| {
            match.deinit();
            return true;
        }
        return false;
    }

    /// Find first match in text
    pub fn find(self: *const Regex, text: []const u8, allocator: std.mem.Allocator) !?Match {
        return self.findAt(text, 0, allocator);
    }

    /// Find match starting at or after position
    pub fn findAt(self: *const Regex, text: []const u8, start: usize, allocator: std.mem.Allocator) !?Match {
        // Use SIMD literal prefix search to skip non-matching positions
        var search_start = start;

        if (self.anchored_start) {
            if (start == 0) {
                return self.matchAt(text, 0, allocator);
            }
            return null;
        }

        while (search_start <= text.len) {
            // Fast skip using literal prefix
            if (self.getLiteralPrefix()) |prefix| {
                if (simd.searchLiteral(text[search_start..], prefix, self.case_insensitive)) |offset| {
                    search_start += offset;
                } else {
                    return null;
                }
            }

            if (try self.matchAt(text, search_start, allocator)) |m| {
                return m;
            }
            search_start += 1;
        }
        return null;
    }

    /// Find all matches in text
    pub fn findAll(self: *const Regex, text: []const u8, allocator: std.mem.Allocator) ![]Match {
        var matches: std.ArrayListUnmanaged(Match) = .{};
        errdefer {
            for (matches.items) |*m| m.deinit();
            matches.deinit(allocator);
        }

        var pos: usize = 0;
        while (pos <= text.len) {
            if (try self.findAt(text, pos, allocator)) |m| {
                try matches.append(allocator, m);
                pos = if (m.end > m.start) m.end else m.start + 1;
            } else {
                break;
            }
        }

        return matches.toOwnedSlice(allocator);
    }

    /// Try to match at exact position
    fn matchAt(self: *const Regex, text: []const u8, pos: usize, allocator: std.mem.Allocator) !?Match {
        var executor = try Executor.init(allocator, self);
        defer executor.deinit();
        return executor.execute(text, pos);
    }

    pub const Options = struct {
        case_insensitive: bool = false,
        multiline: bool = false,
        extended: bool = true, // ERE mode (default)
    };
};

/// State types for the NFA
pub const StateType = enum(u8) {
    literal, // Match single character
    char_class, // Match character class using bitmap
    dot, // Match any character except newline
    split, // Epsilon split to two states
    match, // Accept state
    group_start, // Capture group start
    group_end, // Capture group end
    word_boundary, // \b
    not_word_boundary, // \B
    line_start, // ^
    line_end, // $
    any, // . including newline (with DOTALL flag)
    // PCRE extensions
    lookahead_pos, // (?=...) positive lookahead
    lookahead_neg, // (?!...) negative lookahead
    lookbehind_pos, // (?<=...) positive lookbehind
    lookbehind_neg, // (?<!...) negative lookbehind
};

pub const State = struct {
    pub const Data = union {
        literal: struct {
            char: u8,
            case_insensitive: bool,
        },
        char_class: struct {
            bitmap: *simd.CharClass,
            negated: bool,
        },
        group_idx: u32,
        /// For lookahead/lookbehind assertions
        lookaround: struct {
            sub_pattern_start: u32, // NFA state index where sub-pattern starts
            sub_pattern_len: u32, // For lookbehind: fixed length (0 for lookahead)
        },
        none: void,
    };

    pub const NONE: u32 = std.math.maxInt(u32);

    type: StateType,
    /// Next state (for non-split states)
    out: u32,
    /// Second output for split states
    out2: u32,
    data: Data,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        if (self.type == .char_class) {
            allocator.destroy(self.data.char_class.bitmap);
        }
    }
};

/// Regex compiler - converts pattern string to NFA states
const Compiler = struct {
    allocator: std.mem.Allocator,
    pattern: []const u8,
    pos: usize,
    options: Regex.Options,
    states: std.ArrayListUnmanaged(State),
    group_count: u32,

    const Error = RegexError || std.mem.Allocator.Error;

    fn init(allocator: std.mem.Allocator, pattern: []const u8, options: Regex.Options) Compiler {
        return .{
            .allocator = allocator,
            .pattern = pattern,
            .pos = 0,
            .options = options,
            .states = .{},
            .group_count = 0,
        };
    }

    fn compile(self: *Compiler) !Regex {
        var anchored_start = false;
        var anchored_end = false;

        // Check for ^ anchor at start - but in multiline mode, let it be parsed as line_start
        if (!self.options.multiline and self.pos < self.pattern.len and self.pattern[self.pos] == '^') {
            anchored_start = true;
            self.pos += 1;
        }

        const start_state = try self.parseExpr();

        // Check for $ anchor at end - but in multiline mode, let it be parsed as line_end
        if (!self.options.multiline and self.pos < self.pattern.len and self.pattern[self.pos] == '$') {
            anchored_end = true;
            self.pos += 1;
        }

        if (self.pos != self.pattern.len) {
            for (self.states.items) |*s| s.deinit(self.allocator);
            self.states.deinit(self.allocator);
            return RegexError.InvalidPattern;
        }

        // Add match state
        const match_idx = try self.addState(.{
            .type = .match,
            .out = State.NONE,
            .out2 = State.NONE,
            .data = .{ .none = {} },
        });

        // Patch dangling ends to match state
        try self.patchEnds(start_state, match_idx);

        // Extract literal prefix for SIMD optimization
        var literal_prefix_storage: [64]u8 = undefined;
        const literal_prefix_len = self.extractLiteralPrefix(&literal_prefix_storage, start_state);

        return Regex{
            .allocator = self.allocator,
            .states = try self.states.toOwnedSlice(self.allocator),
            .start_state = start_state,
            .num_groups = self.group_count,
            .anchored_start = anchored_start,
            .anchored_end = anchored_end,
            .literal_prefix_storage = literal_prefix_storage,
            .literal_prefix_len = literal_prefix_len,
            .case_insensitive = self.options.case_insensitive,
            .multiline = self.options.multiline,
        };
    }

    fn extractLiteralPrefix(self: *Compiler, storage: *[64]u8, start_state: u32) usize {
        // Find leading literal characters for SIMD skip optimization
        // Don't extract prefix for alternations (split states) as each branch may differ
        if (self.states.items.len == 0) return 0;
        if (start_state >= self.states.items.len) return 0;
        if (self.states.items[start_state].type == .split) return 0;

        var len: usize = 0;
        var state_idx: u32 = start_state;

        while (state_idx < self.states.items.len and len < 64) {
            const state = &self.states.items[state_idx];
            switch (state.type) {
                .literal => {
                    storage[len] = if (self.options.case_insensitive)
                        simd.toLower(state.data.literal.char)
                    else
                        state.data.literal.char;
                    len += 1;
                    state_idx = state.out;
                    if (state_idx == State.NONE) break;
                },
                .group_start, .group_end => {
                    state_idx = state.out;
                    if (state_idx == State.NONE) break;
                },
                else => break,
            }
        }

        return len;
    }

    fn parseExpr(self: *Compiler) Error!u32 {
        var left = try self.parseTerm();

        while (self.pos < self.pattern.len and self.pattern[self.pos] == '|') {
            self.pos += 1;
            const right = try self.parseTerm();

            // Create split state for alternation
            const split_idx = try self.addState(.{
                .type = .split,
                .out = left,
                .out2 = right,
                .data = .{ .none = {} },
            });

            left = split_idx;
        }

        return left;
    }

    fn parseTerm(self: *Compiler) Error!u32 {
        var result: ?u32 = null;

        while (self.pos < self.pattern.len) {
            const c = self.pattern[self.pos];
            if (c == '|' or c == ')') break;

            const factor = try self.parseFactor();

            if (result) |r| {
                try self.patchEnds(r, factor);
                // result stays the same (start of concatenation)
            } else {
                result = factor;
            }
        }

        // Empty pattern - epsilon
        if (result == null) {
            result = try self.addState(.{
                .type = .split,
                .out = State.NONE,
                .out2 = State.NONE,
                .data = .{ .none = {} },
            });
        }

        return result.?;
    }

    fn parseFactor(self: *Compiler) Error!u32 {
        var base = try self.parseBase();

        // Handle quantifiers
        if (self.pos < self.pattern.len) {
            switch (self.pattern[self.pos]) {
                '*' => {
                    self.pos += 1;
                    base = try self.makeKleeneStar(base);
                },
                '+' => {
                    self.pos += 1;
                    base = try self.makeOneOrMore(base);
                },
                '?' => {
                    self.pos += 1;
                    base = try self.makeOptional(base);
                },
                '{' => {
                    base = try self.parseQuantifier(base);
                },
                else => {},
            }
        }

        return base;
    }

    fn parseBase(self: *Compiler) Error!u32 {
        if (self.pos >= self.pattern.len) {
            return RegexError.InvalidPattern;
        }

        const c = self.pattern[self.pos];
        switch (c) {
            '(' => {
                self.pos += 1;

                // Check for PCRE extensions: (?=...), (?!...), (?<=...), (?<!...), (?:...)
                if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                    self.pos += 1;
                    if (self.pos >= self.pattern.len) return RegexError.InvalidPattern;

                    const ext_char = self.pattern[self.pos];
                    switch (ext_char) {
                        '=' => {
                            // Positive lookahead (?=...)
                            self.pos += 1;
                            return self.parseLookaround(.lookahead_pos);
                        },
                        '!' => {
                            // Negative lookahead (?!...)
                            self.pos += 1;
                            return self.parseLookaround(.lookahead_neg);
                        },
                        '<' => {
                            // Lookbehind: (?<=...) or (?<!...)
                            self.pos += 1;
                            if (self.pos >= self.pattern.len) return RegexError.InvalidPattern;
                            const lb_char = self.pattern[self.pos];
                            if (lb_char == '=') {
                                self.pos += 1;
                                return self.parseLookaround(.lookbehind_pos);
                            } else if (lb_char == '!') {
                                self.pos += 1;
                                return self.parseLookaround(.lookbehind_neg);
                            }
                            return RegexError.InvalidPattern; // Named groups not supported
                        },
                        ':' => {
                            // Non-capturing group (?:...) - parse like normal group but don't increment group count
                            self.pos += 1;
                            const inner = try self.parseExpr();
                            if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') {
                                return RegexError.UnmatchedParen;
                            }
                            self.pos += 1;
                            return inner;
                        },
                        else => return RegexError.InvalidPattern,
                    }
                }

                // Regular capturing group
                self.group_count += 1;
                const group_idx = self.group_count;

                const start = try self.addState(.{
                    .type = .group_start,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .group_idx = group_idx },
                });

                const inner = try self.parseExpr();

                if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') {
                    return RegexError.UnmatchedParen;
                }
                self.pos += 1;

                const end = try self.addState(.{
                    .type = .group_end,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .group_idx = group_idx },
                });

                self.states.items[start].out = inner;
                try self.patchEnds(inner, end);

                return start;
            },
            '[' => return self.parseCharClass(),
            '.' => {
                self.pos += 1;
                return self.addState(.{
                    .type = .dot,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .none = {} },
                });
            },
            '^' => {
                self.pos += 1;
                return self.addState(.{
                    .type = .line_start,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .none = {} },
                });
            },
            '$' => {
                self.pos += 1;
                return self.addState(.{
                    .type = .line_end,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .none = {} },
                });
            },
            '\\' => return self.parseEscape(),
            '*', '+', '?', '{', '|', ')' => return RegexError.InvalidPattern,
            else => {
                self.pos += 1;
                return self.addState(.{
                    .type = .literal,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .literal = .{
                        .char = c,
                        .case_insensitive = self.options.case_insensitive,
                    } },
                });
            },
        }
    }

    fn parseCharClass(self: *Compiler) Error!u32 {
        self.pos += 1; // skip [

        var negated = false;
        if (self.pos < self.pattern.len and self.pattern[self.pos] == '^') {
            negated = true;
            self.pos += 1;
        }

        const bitmap = try self.allocator.create(simd.CharClass);
        bitmap.* = simd.CharClass.init();

        // Handle ] as first character (literal)
        if (self.pos < self.pattern.len and self.pattern[self.pos] == ']') {
            bitmap.addChar(']');
            self.pos += 1;
        }

        while (self.pos < self.pattern.len and self.pattern[self.pos] != ']') {
            const start_char = self.pattern[self.pos];

            // Check for POSIX character class [:classname:]
            if (start_char == '[' and self.pos + 1 < self.pattern.len and self.pattern[self.pos + 1] == ':') {
                if (try self.parsePosixClass(bitmap)) {
                    continue;
                }
            }

            self.pos += 1;

            // Handle escape sequences in character class
            var actual_start = start_char;
            if (start_char == '\\' and self.pos < self.pattern.len) {
                actual_start = switch (self.pattern[self.pos]) {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    'd' => {
                        // Add digit class
                        bitmap.addRange('0', '9');
                        self.pos += 1;
                        continue;
                    },
                    'w' => {
                        bitmap.addRange('a', 'z');
                        bitmap.addRange('A', 'Z');
                        bitmap.addRange('0', '9');
                        bitmap.addChar('_');
                        self.pos += 1;
                        continue;
                    },
                    's' => {
                        bitmap.addChar(' ');
                        bitmap.addChar('\t');
                        bitmap.addChar('\n');
                        bitmap.addChar('\r');
                        self.pos += 1;
                        continue;
                    },
                    else => self.pattern[self.pos],
                };
                self.pos += 1;
            }

            // Check for range
            if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                self.pos += 1; // skip -
                var end_char = self.pattern[self.pos];
                self.pos += 1;

                // Handle escape in range end
                if (end_char == '\\' and self.pos < self.pattern.len) {
                    end_char = switch (self.pattern[self.pos]) {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        else => self.pattern[self.pos],
                    };
                    self.pos += 1;
                }

                if (actual_start > end_char) {
                    self.allocator.destroy(bitmap);
                    return RegexError.InvalidRange;
                }
                bitmap.addRange(actual_start, end_char);
            } else {
                bitmap.addChar(actual_start);
            }
        }

        if (self.pos >= self.pattern.len) {
            self.allocator.destroy(bitmap);
            return RegexError.UnmatchedBracket;
        }
        self.pos += 1; // skip ]

        if (negated) {
            bitmap.negate();
        }

        return self.addState(.{
            .type = .char_class,
            .out = State.NONE,
            .out2 = State.NONE,
            .data = .{ .char_class = .{ .bitmap = bitmap, .negated = false } },
        });
    }

    /// Parse POSIX character class like [:alnum:], [:alpha:], etc.
    /// Returns true if a POSIX class was parsed, false otherwise
    fn parsePosixClass(self: *Compiler, bitmap: *simd.CharClass) Error!bool {
        // Check for [:classname:] pattern
        if (self.pos + 2 >= self.pattern.len) return false;
        if (self.pattern[self.pos] != '[' or self.pattern[self.pos + 1] != ':') return false;

        // Find the closing :]
        var class_end: usize = self.pos + 2;
        while (class_end + 1 < self.pattern.len) {
            if (self.pattern[class_end] == ':' and self.pattern[class_end + 1] == ']') {
                break;
            }
            class_end += 1;
        }

        if (class_end + 1 >= self.pattern.len) return false;

        const class_name = self.pattern[self.pos + 2 .. class_end];

        // Match POSIX class names and add appropriate characters
        if (std.mem.eql(u8, class_name, "alnum")) {
            bitmap.addRange('a', 'z');
            bitmap.addRange('A', 'Z');
            bitmap.addRange('0', '9');
        } else if (std.mem.eql(u8, class_name, "alpha")) {
            bitmap.addRange('a', 'z');
            bitmap.addRange('A', 'Z');
        } else if (std.mem.eql(u8, class_name, "digit")) {
            bitmap.addRange('0', '9');
        } else if (std.mem.eql(u8, class_name, "space")) {
            bitmap.addChar(' ');
            bitmap.addChar('\t');
            bitmap.addChar('\n');
            bitmap.addChar('\r');
            bitmap.addChar(0x0B); // vertical tab
            bitmap.addChar(0x0C); // form feed
        } else if (std.mem.eql(u8, class_name, "lower")) {
            bitmap.addRange('a', 'z');
        } else if (std.mem.eql(u8, class_name, "upper")) {
            bitmap.addRange('A', 'Z');
        } else if (std.mem.eql(u8, class_name, "blank")) {
            bitmap.addChar(' ');
            bitmap.addChar('\t');
        } else if (std.mem.eql(u8, class_name, "cntrl")) {
            bitmap.addRange(0, 31);
            bitmap.addChar(127);
        } else if (std.mem.eql(u8, class_name, "graph")) {
            bitmap.addRange('!', '~'); // 0x21-0x7E
        } else if (std.mem.eql(u8, class_name, "print")) {
            bitmap.addRange(' ', '~'); // 0x20-0x7E
        } else if (std.mem.eql(u8, class_name, "punct")) {
            // Punctuation: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
            bitmap.addRange('!', '/'); // !"#$%&'()*+,-./
            bitmap.addRange(':', '@'); // :;<=>?@
            bitmap.addRange('[', '`'); // [\]^_`
            bitmap.addRange('{', '~'); // {|}~
        } else if (std.mem.eql(u8, class_name, "xdigit")) {
            bitmap.addRange('0', '9');
            bitmap.addRange('a', 'f');
            bitmap.addRange('A', 'F');
        } else if (std.mem.eql(u8, class_name, "word")) {
            // GNU extension: equivalent to \w
            bitmap.addRange('a', 'z');
            bitmap.addRange('A', 'Z');
            bitmap.addRange('0', '9');
            bitmap.addChar('_');
        } else {
            // Unknown class name - treat as literal
            return false;
        }

        // Advance past [:classname:]
        self.pos = class_end + 2;
        return true;
    }

    fn parseEscape(self: *Compiler) Error!u32 {
        self.pos += 1;
        if (self.pos >= self.pattern.len) return RegexError.InvalidEscape;

        const c = self.pattern[self.pos];
        self.pos += 1;

        switch (c) {
            'd' => {
                const bitmap = try self.allocator.create(simd.CharClass);
                bitmap.* = simd.CharClass.digit;
                return self.addState(.{
                    .type = .char_class,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .char_class = .{ .bitmap = bitmap, .negated = false } },
                });
            },
            'D' => {
                const bitmap = try self.allocator.create(simd.CharClass);
                bitmap.* = simd.CharClass.not_digit;
                return self.addState(.{
                    .type = .char_class,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .char_class = .{ .bitmap = bitmap, .negated = false } },
                });
            },
            'w' => {
                const bitmap = try self.allocator.create(simd.CharClass);
                bitmap.* = simd.CharClass.word;
                return self.addState(.{
                    .type = .char_class,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .char_class = .{ .bitmap = bitmap, .negated = false } },
                });
            },
            'W' => {
                const bitmap = try self.allocator.create(simd.CharClass);
                bitmap.* = simd.CharClass.not_word;
                return self.addState(.{
                    .type = .char_class,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .char_class = .{ .bitmap = bitmap, .negated = false } },
                });
            },
            's' => {
                const bitmap = try self.allocator.create(simd.CharClass);
                bitmap.* = simd.CharClass.whitespace;
                return self.addState(.{
                    .type = .char_class,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .char_class = .{ .bitmap = bitmap, .negated = false } },
                });
            },
            'S' => {
                const bitmap = try self.allocator.create(simd.CharClass);
                bitmap.* = simd.CharClass.not_whitespace;
                return self.addState(.{
                    .type = .char_class,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .char_class = .{ .bitmap = bitmap, .negated = false } },
                });
            },
            'b' => {
                return self.addState(.{
                    .type = .word_boundary,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .none = {} },
                });
            },
            'B' => {
                return self.addState(.{
                    .type = .not_word_boundary,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .none = {} },
                });
            },
            'n' => {
                return self.addState(.{
                    .type = .literal,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .literal = .{ .char = '\n', .case_insensitive = false } },
                });
            },
            't' => {
                return self.addState(.{
                    .type = .literal,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .literal = .{ .char = '\t', .case_insensitive = false } },
                });
            },
            'r' => {
                return self.addState(.{
                    .type = .literal,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .literal = .{ .char = '\r', .case_insensitive = false } },
                });
            },
            else => {
                // Escaped literal
                return self.addState(.{
                    .type = .literal,
                    .out = State.NONE,
                    .out2 = State.NONE,
                    .data = .{ .literal = .{
                        .char = c,
                        .case_insensitive = self.options.case_insensitive,
                    } },
                });
            },
        }
    }

    /// Parse a lookaround assertion: (?=...), (?!...), (?<=...), (?<!...)
    fn parseLookaround(self: *Compiler, state_type: StateType) Error!u32 {
        // Record start of sub-pattern states
        const sub_pattern_start: u32 = @intCast(self.states.items.len);

        // Parse the sub-pattern inside the lookaround
        const inner = try self.parseExpr();

        if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') {
            return RegexError.UnmatchedParen;
        }
        self.pos += 1;

        // Add a match state at the end of the sub-pattern (for sub-pattern matching)
        const sub_match_idx = try self.addState(.{
            .type = .match,
            .out = State.NONE,
            .out2 = State.NONE,
            .data = .{ .none = {} },
        });
        try self.patchEnds(inner, sub_match_idx);

        // For lookbehind, compute the fixed length of the sub-pattern
        var fixed_length: u32 = 0;
        if (state_type == .lookbehind_pos or state_type == .lookbehind_neg) {
            fixed_length = self.computeFixedLength(inner) orelse {
                // Lookbehind must have fixed length
                return RegexError.PatternTooComplex;
            };
        }

        // Create the lookaround state
        return self.addState(.{
            .type = state_type,
            .out = State.NONE, // Will be patched by caller to continue after assertion
            .out2 = State.NONE,
            .data = .{ .lookaround = .{
                .sub_pattern_start = sub_pattern_start,
                .sub_pattern_len = fixed_length,
            } },
        });
    }

    /// Compute the fixed length of a sub-pattern for lookbehind
    /// Returns null if the pattern has variable length (contains *, +, ?, etc.)
    fn computeFixedLength(self: *Compiler, start_idx: u32) ?u32 {
        if (start_idx >= self.states.items.len) return 0;

        var length: u32 = 0;
        var idx = start_idx;
        var visited = std.AutoHashMap(u32, void).init(self.allocator);
        defer visited.deinit();

        while (idx < self.states.items.len) {
            if (visited.get(idx) != null) break;
            visited.put(idx, {}) catch return null;

            const state = &self.states.items[idx];
            switch (state.type) {
                .literal, .char_class, .dot, .any => {
                    length += 1;
                    idx = state.out;
                    if (idx == State.NONE) break;
                },
                .split => {
                    // Variable length - alternation or quantifier
                    // For alternation, both branches must have same length
                    const len1 = self.computeFixedLength(state.out);
                    const len2 = self.computeFixedLength(state.out2);
                    if (len1 != null and len2 != null and len1.? == len2.?) {
                        return length + len1.?;
                    }
                    return null;
                },
                .group_start, .group_end, .line_start, .line_end, .word_boundary, .not_word_boundary => {
                    // Zero-width - continue
                    idx = state.out;
                    if (idx == State.NONE) break;
                },
                .match => break,
                else => return null,
            }
        }

        return length;
    }

    fn parseQuantifier(self: *Compiler, base: u32) Error!u32 {
        self.pos += 1; // skip {

        var min: u32 = 0;
        var max: ?u32 = null;

        while (self.pos < self.pattern.len and self.pattern[self.pos] >= '0' and self.pattern[self.pos] <= '9') {
            min = min * 10 + @as(u32, self.pattern[self.pos] - '0');
            self.pos += 1;
        }

        if (self.pos < self.pattern.len and self.pattern[self.pos] == ',') {
            self.pos += 1;
            if (self.pos < self.pattern.len and self.pattern[self.pos] >= '0' and self.pattern[self.pos] <= '9') {
                max = 0;
                while (self.pos < self.pattern.len and self.pattern[self.pos] >= '0' and self.pattern[self.pos] <= '9') {
                    max = max.? * 10 + @as(u32, self.pattern[self.pos] - '0');
                    self.pos += 1;
                }
            }
        } else {
            max = min;
        }

        if (self.pos >= self.pattern.len or self.pattern[self.pos] != '}') {
            return RegexError.InvalidQuantifier;
        }
        self.pos += 1;

        // Simplified quantifier handling
        if (min == 0 and max == null) {
            return self.makeKleeneStar(base);
        } else if (min == 1 and max == null) {
            return self.makeOneOrMore(base);
        } else if (min == 0 and max != null and max.? == 1) {
            return self.makeOptional(base);
        }

        // For {n,m} we'd need to duplicate states - fall back to base for now
        return base;
    }

    fn makeKleeneStar(self: *Compiler, base: u32) Error!u32 {
        const split = try self.addState(.{
            .type = .split,
            .out = base,
            .out2 = State.NONE,
            .data = .{ .none = {} },
        });
        try self.patchEnds(base, split);
        return split;
    }

    fn makeOneOrMore(self: *Compiler, base: u32) Error!u32 {
        const split = try self.addState(.{
            .type = .split,
            .out = base,
            .out2 = State.NONE,
            .data = .{ .none = {} },
        });
        try self.patchEnds(base, split);
        return base;
    }

    fn makeOptional(self: *Compiler, base: u32) Error!u32 {
        const split = try self.addState(.{
            .type = .split,
            .out = base,
            .out2 = State.NONE,
            .data = .{ .none = {} },
        });
        return split;
    }

    fn addState(self: *Compiler, state: State) Error!u32 {
        const idx = @as(u32, @intCast(self.states.items.len));
        try self.states.append(self.allocator, state);
        return idx;
    }

    fn patchEnds(self: *Compiler, start: u32, target: u32) Error!void {
        const visited = try self.allocator.alloc(bool, self.states.items.len);
        defer self.allocator.free(visited);
        @memset(visited, false);

        self.patchEndsRecursive(start, target, visited);
    }

    fn patchEndsRecursive(self: *Compiler, idx: u32, target: u32, visited: []bool) void {
        if (idx == State.NONE or idx >= self.states.items.len) return;
        if (visited[idx]) return;
        visited[idx] = true;

        const state = &self.states.items[idx];

        switch (state.type) {
            .split => {
                if (state.out == State.NONE) {
                    state.out = target;
                } else {
                    self.patchEndsRecursive(state.out, target, visited);
                }
                if (state.out2 == State.NONE) {
                    state.out2 = target;
                } else {
                    self.patchEndsRecursive(state.out2, target, visited);
                }
            },
            .match => {},
            else => {
                if (state.out == State.NONE) {
                    state.out = target;
                } else {
                    self.patchEndsRecursive(state.out, target, visited);
                }
            },
        }
    }
};

/// NFA executor with Thompson's algorithm
const Executor = struct {
    allocator: std.mem.Allocator,
    regex: *const Regex,
    current: std.ArrayListUnmanaged(u32),
    next: std.ArrayListUnmanaged(u32),
    groups: []?Match.Group,
    in_current: []bool,

    fn init(allocator: std.mem.Allocator, regex: *const Regex) !Executor {
        const groups = try allocator.alloc(?Match.Group, regex.num_groups + 1);
        @memset(groups, null);

        const in_current = try allocator.alloc(bool, regex.states.len);
        @memset(in_current, false);

        return .{
            .allocator = allocator,
            .regex = regex,
            .current = .{},
            .next = .{},
            .groups = groups,
            .in_current = in_current,
        };
    }

    fn deinit(self: *Executor) void {
        self.current.deinit(self.allocator);
        self.next.deinit(self.allocator);
        self.allocator.free(self.in_current);
        // groups ownership transferred to Match or freed here
    }

    fn execute(self: *Executor, text: []const u8, start: usize) !?Match {
        self.current.clearRetainingCapacity();
        @memset(self.in_current, false);

        try self.addState(self.regex.start_state, start, text);

        var pos = start;
        var last_match: ?Match = null;

        while (pos <= text.len) {
            // Check for match state
            for (self.current.items) |idx| {
                if (self.regex.states[idx].type == .match) {
                    if (!self.regex.anchored_end or pos == text.len) {
                        // Found a match - save it
                        const groups_copy = try self.allocator.dupe(?Match.Group, self.groups);
                        if (last_match) |*m| m.deinit();
                        last_match = Match{
                            .start = start,
                            .end = pos,
                            .groups = groups_copy,
                            .allocator = self.allocator,
                        };
                    }
                }
            }

            if (pos == text.len) break;

            // Process transitions
            self.next.clearRetainingCapacity();
            @memset(self.in_current, false);

            const c = text[pos];

            for (self.current.items) |idx| {
                const state = &self.regex.states[idx];
                if (self.matchState(state, text, pos, c)) {
                    if (state.out != State.NONE) {
                        try self.addStateToNext(state.out, pos + 1, text);
                    }
                }
            }

            // Swap current and next
            const tmp = self.current;
            self.current = self.next;
            self.next = tmp;

            if (self.current.items.len == 0) break;
            pos += 1;
        }

        if (last_match) |m| {
            // Transfer groups ownership
            self.allocator.free(self.groups);
            self.groups = @constCast(&[_]?Match.Group{});
            return m;
        }

        self.allocator.free(self.groups);
        self.groups = @constCast(&[_]?Match.Group{});
        return null;
    }

    fn matchState(self: *Executor, state: *const State, text: []const u8, pos: usize, c: u8) bool {
        _ = self;
        _ = text;
        _ = pos;
        switch (state.type) {
            .literal => {
                const lit = state.data.literal;
                if (lit.case_insensitive) {
                    return simd.toLower(c) == simd.toLower(lit.char);
                }
                return c == lit.char;
            },
            .char_class => {
                return state.data.char_class.bitmap.contains(c);
            },
            .dot => return c != '\n',
            .any => return true,
            // Zero-width assertions are handled in addState/addStateToNext as epsilon transitions
            else => return false,
        }
    }

    fn addState(self: *Executor, idx: u32, pos: usize, text: []const u8) !void {
        if (idx == State.NONE or idx >= self.regex.states.len) return;
        if (self.in_current[idx]) return;

        const state = &self.regex.states[idx];

        switch (state.type) {
            .split => {
                try self.addState(state.out, pos, text);
                try self.addState(state.out2, pos, text);
            },
            .group_start => {
                const gidx = state.data.group_idx;
                if (gidx < self.groups.len) {
                    self.groups[gidx] = .{ .start = pos, .end = pos };
                }
                try self.addState(state.out, pos, text);
            },
            .group_end => {
                const gidx = state.data.group_idx;
                if (gidx < self.groups.len) {
                    if (self.groups[gidx]) |*g| {
                        g.end = pos;
                    }
                }
                try self.addState(state.out, pos, text);
            },
            // Zero-width assertions: check condition and follow epsilon transition if satisfied
            .line_start => {
                if (pos == 0 or (pos > 0 and text[pos - 1] == '\n')) {
                    try self.addState(state.out, pos, text);
                }
            },
            .line_end => {
                if (pos == text.len or (pos < text.len and text[pos] == '\n')) {
                    try self.addState(state.out, pos, text);
                }
            },
            .word_boundary => {
                if (simd.isWordBoundary(text, pos)) {
                    try self.addState(state.out, pos, text);
                }
            },
            .not_word_boundary => {
                if (!simd.isWordBoundary(text, pos)) {
                    try self.addState(state.out, pos, text);
                }
            },
            .lookahead_pos => {
                // Positive lookahead: continue only if sub-pattern matches at pos
                const la_data = state.data.lookaround;
                if (try self.matchSubPattern(text, pos, la_data.sub_pattern_start)) {
                    try self.addState(state.out, pos, text);
                }
            },
            .lookahead_neg => {
                // Negative lookahead: continue only if sub-pattern does NOT match at pos
                const la_data = state.data.lookaround;
                if (!try self.matchSubPattern(text, pos, la_data.sub_pattern_start)) {
                    try self.addState(state.out, pos, text);
                }
            },
            .lookbehind_pos => {
                // Positive lookbehind: continue only if sub-pattern matches ending at pos
                const lb_data = state.data.lookaround;
                const len = lb_data.sub_pattern_len;
                if (pos >= len) {
                    if (try self.matchSubPatternExact(text, pos - len, lb_data.sub_pattern_start, len)) {
                        try self.addState(state.out, pos, text);
                    }
                }
            },
            .lookbehind_neg => {
                // Negative lookbehind: continue only if sub-pattern does NOT match ending at pos
                const lb_data = state.data.lookaround;
                const len = lb_data.sub_pattern_len;
                if (pos < len or !try self.matchSubPatternExact(text, pos - len, lb_data.sub_pattern_start, len)) {
                    try self.addState(state.out, pos, text);
                }
            },
            else => {
                self.in_current[idx] = true;
                try self.current.append(self.allocator, idx);
            },
        }
    }

    fn addStateToNext(self: *Executor, idx: u32, pos: usize, text: []const u8) !void {
        if (idx == State.NONE or idx >= self.regex.states.len) return;

        const state = &self.regex.states[idx];

        switch (state.type) {
            .split => {
                try self.addStateToNext(state.out, pos, text);
                try self.addStateToNext(state.out2, pos, text);
            },
            .group_start => {
                const gidx = state.data.group_idx;
                if (gidx < self.groups.len) {
                    self.groups[gidx] = .{ .start = pos, .end = pos };
                }
                try self.addStateToNext(state.out, pos, text);
            },
            .group_end => {
                const gidx = state.data.group_idx;
                if (gidx < self.groups.len) {
                    if (self.groups[gidx]) |*g| {
                        g.end = pos;
                    }
                }
                try self.addStateToNext(state.out, pos, text);
            },
            // Zero-width assertions: check condition and follow epsilon transition if satisfied
            .line_start => {
                if (pos == 0 or (pos > 0 and text[pos - 1] == '\n')) {
                    try self.addStateToNext(state.out, pos, text);
                }
            },
            .line_end => {
                if (pos == text.len or (pos < text.len and text[pos] == '\n')) {
                    try self.addStateToNext(state.out, pos, text);
                }
            },
            .word_boundary => {
                if (simd.isWordBoundary(text, pos)) {
                    try self.addStateToNext(state.out, pos, text);
                }
            },
            .not_word_boundary => {
                if (!simd.isWordBoundary(text, pos)) {
                    try self.addStateToNext(state.out, pos, text);
                }
            },
            .lookahead_pos => {
                const la_data = state.data.lookaround;
                if (try self.matchSubPattern(text, pos, la_data.sub_pattern_start)) {
                    try self.addStateToNext(state.out, pos, text);
                }
            },
            .lookahead_neg => {
                const la_data = state.data.lookaround;
                if (!try self.matchSubPattern(text, pos, la_data.sub_pattern_start)) {
                    try self.addStateToNext(state.out, pos, text);
                }
            },
            .lookbehind_pos => {
                const lb_data = state.data.lookaround;
                const len = lb_data.sub_pattern_len;
                if (pos >= len) {
                    if (try self.matchSubPatternExact(text, pos - len, lb_data.sub_pattern_start, len)) {
                        try self.addStateToNext(state.out, pos, text);
                    }
                }
            },
            .lookbehind_neg => {
                const lb_data = state.data.lookaround;
                const len = lb_data.sub_pattern_len;
                if (pos < len or !try self.matchSubPatternExact(text, pos - len, lb_data.sub_pattern_start, len)) {
                    try self.addStateToNext(state.out, pos, text);
                }
            },
            else => {
                // Check for duplicates
                for (self.next.items) |existing| {
                    if (existing == idx) return;
                }
                try self.next.append(self.allocator, idx);
            },
        }
    }

    /// Check if sub-pattern matches starting at pos (for lookahead)
    fn matchSubPattern(self: *Executor, text: []const u8, pos: usize, sub_start: u32) !bool {
        // Simple recursive sub-pattern matching
        // We need to check if the sub-pattern can match starting at pos
        var sub_current: std.ArrayListUnmanaged(u32) = .{};
        defer sub_current.deinit(self.allocator);
        var sub_next: std.ArrayListUnmanaged(u32) = .{};
        defer sub_next.deinit(self.allocator);

        // Initialize with epsilon closure from sub_start
        try self.addSubState(&sub_current, sub_start, pos, text);

        var sub_pos = pos;
        while (sub_pos <= text.len) {
            // Check for match state in sub-pattern
            for (sub_current.items) |idx| {
                if (idx < self.regex.states.len and self.regex.states[idx].type == .match) {
                    return true;
                }
            }

            if (sub_pos == text.len) break;

            // Process character transitions
            sub_next.clearRetainingCapacity();
            const c = text[sub_pos];

            for (sub_current.items) |idx| {
                if (idx >= self.regex.states.len) continue;
                const state = &self.regex.states[idx];
                if (self.matchState(state, text, sub_pos, c)) {
                    if (state.out != State.NONE) {
                        try self.addSubState(&sub_next, state.out, sub_pos + 1, text);
                    }
                }
            }

            const tmp = sub_current;
            sub_current = sub_next;
            sub_next = tmp;

            if (sub_current.items.len == 0) break;
            sub_pos += 1;
        }

        // Final check for match state
        for (sub_current.items) |idx| {
            if (idx < self.regex.states.len and self.regex.states[idx].type == .match) {
                return true;
            }
        }

        return false;
    }

    /// Check if sub-pattern matches exactly 'len' characters starting at pos (for lookbehind)
    fn matchSubPatternExact(self: *Executor, text: []const u8, pos: usize, sub_start: u32, len: u32) !bool {
        if (pos + len > text.len) return false;

        var sub_current: std.ArrayListUnmanaged(u32) = .{};
        defer sub_current.deinit(self.allocator);
        var sub_next: std.ArrayListUnmanaged(u32) = .{};
        defer sub_next.deinit(self.allocator);

        try self.addSubState(&sub_current, sub_start, pos, text);

        var chars_consumed: u32 = 0;
        var sub_pos = pos;

        while (chars_consumed < len and sub_pos < text.len) {
            sub_next.clearRetainingCapacity();
            const c = text[sub_pos];

            for (sub_current.items) |idx| {
                if (idx >= self.regex.states.len) continue;
                const state = &self.regex.states[idx];
                if (self.matchState(state, text, sub_pos, c)) {
                    if (state.out != State.NONE) {
                        try self.addSubState(&sub_next, state.out, sub_pos + 1, text);
                    }
                }
            }

            const tmp = sub_current;
            sub_current = sub_next;
            sub_next = tmp;

            if (sub_current.items.len == 0) break;
            sub_pos += 1;
            chars_consumed += 1;
        }

        // Check if we consumed exactly len chars and reached match state
        if (chars_consumed == len) {
            for (sub_current.items) |idx| {
                if (idx < self.regex.states.len and self.regex.states[idx].type == .match) {
                    return true;
                }
            }
        }

        return false;
    }

    /// Add state to sub-pattern state list with epsilon closure
    fn addSubState(self: *Executor, list: *std.ArrayListUnmanaged(u32), idx: u32, pos: usize, text: []const u8) !void {
        if (idx == State.NONE or idx >= self.regex.states.len) return;

        // Check for duplicates
        for (list.items) |existing| {
            if (existing == idx) return;
        }

        const state = &self.regex.states[idx];
        switch (state.type) {
            .split => {
                try self.addSubState(list, state.out, pos, text);
                try self.addSubState(list, state.out2, pos, text);
            },
            .group_start, .group_end => {
                try self.addSubState(list, state.out, pos, text);
            },
            .line_start => {
                if (pos == 0 or (pos > 0 and text[pos - 1] == '\n')) {
                    try self.addSubState(list, state.out, pos, text);
                }
            },
            .line_end => {
                if (pos == text.len or (pos < text.len and text[pos] == '\n')) {
                    try self.addSubState(list, state.out, pos, text);
                }
            },
            .word_boundary => {
                if (simd.isWordBoundary(text, pos)) {
                    try self.addSubState(list, state.out, pos, text);
                }
            },
            .not_word_boundary => {
                if (!simd.isWordBoundary(text, pos)) {
                    try self.addSubState(list, state.out, pos, text);
                }
            },
            else => {
                try list.append(self.allocator, idx);
            },
        }
    }
};

/// Check if a pattern contains regex metacharacters
pub fn isRegexPattern(pattern: []const u8) bool {
    var i: usize = 0;
    while (i < pattern.len) {
        const c = pattern[i];
        switch (c) {
            '.', '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$' => return true,
            '\\' => {
                if (i + 1 < pattern.len) {
                    switch (pattern[i + 1]) {
                        'd', 'D', 'w', 'W', 's', 'S', 'b', 'B' => return true,
                        else => {},
                    }
                }
                i += 1;
            },
            else => {},
        }
        i += 1;
    }
    return false;
}

// Tests
test "simple literal match" {
    var regex = try Regex.compile(std.testing.allocator, "hello", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("hello world"));
    try std.testing.expect(regex.isMatch("say hello"));
    try std.testing.expect(!regex.isMatch("hell"));
}

test "dot metacharacter" {
    var regex = try Regex.compile(std.testing.allocator, "h.llo", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("hello"));
    try std.testing.expect(regex.isMatch("hallo"));
    try std.testing.expect(!regex.isMatch("hllo"));
}

test "character class" {
    var regex = try Regex.compile(std.testing.allocator, "[abc]", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("a"));
    try std.testing.expect(regex.isMatch("b"));
    try std.testing.expect(regex.isMatch("c"));
    try std.testing.expect(!regex.isMatch("d"));
}

test "negated character class" {
    var regex = try Regex.compile(std.testing.allocator, "[^abc]", .{});
    defer regex.deinit();

    try std.testing.expect(!regex.isMatch("a"));
    try std.testing.expect(regex.isMatch("d"));
    try std.testing.expect(regex.isMatch("z"));
}

test "character range" {
    var regex = try Regex.compile(std.testing.allocator, "[a-z]+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("hello"));
    try std.testing.expect(!regex.isMatch("12345"));
}

test "kleene star" {
    var regex = try Regex.compile(std.testing.allocator, "ab*c", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("ac"));
    try std.testing.expect(regex.isMatch("abc"));
    try std.testing.expect(regex.isMatch("abbc"));
    try std.testing.expect(regex.isMatch("abbbc"));
}

test "plus quantifier" {
    var regex = try Regex.compile(std.testing.allocator, "ab+c", .{});
    defer regex.deinit();

    try std.testing.expect(!regex.isMatch("ac"));
    try std.testing.expect(regex.isMatch("abc"));
    try std.testing.expect(regex.isMatch("abbc"));
}

test "optional quantifier" {
    var regex = try Regex.compile(std.testing.allocator, "colou?r", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("color"));
    try std.testing.expect(regex.isMatch("colour"));
}

test "alternation" {
    var regex = try Regex.compile(std.testing.allocator, "cat|dog", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("cat"));
    try std.testing.expect(regex.isMatch("dog"));
    try std.testing.expect(!regex.isMatch("bird"));
}

test "start anchor" {
    var regex = try Regex.compile(std.testing.allocator, "^hello", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("hello world"));
    try std.testing.expect(!regex.isMatch("say hello"));
}

test "end anchor" {
    var regex = try Regex.compile(std.testing.allocator, "world$", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("hello world"));
    try std.testing.expect(!regex.isMatch("world hello"));
}

test "digit class" {
    var regex = try Regex.compile(std.testing.allocator, "\\d+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("123"));
    try std.testing.expect(regex.isMatch("a123b"));
    try std.testing.expect(!regex.isMatch("abc"));
}

test "word class" {
    var regex = try Regex.compile(std.testing.allocator, "\\w+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("hello"));
    try std.testing.expect(regex.isMatch("hello_123"));
}

test "whitespace class" {
    var regex = try Regex.compile(std.testing.allocator, "\\s+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("  "));
    try std.testing.expect(regex.isMatch("\t\n"));
    try std.testing.expect(!regex.isMatch("abc"));
}

test "capture groups" {
    var regex = try Regex.compile(std.testing.allocator, "(\\w+)@(\\w+)", .{});
    defer regex.deinit();

    const text = "email: user@domain";
    var match = (try regex.find(text, std.testing.allocator)).?;
    defer match.deinit();

    try std.testing.expectEqualStrings("user@domain", match.text(text));
    try std.testing.expectEqualStrings("user", match.group(1, text).?);
    try std.testing.expectEqualStrings("domain", match.group(2, text).?);
}

test "case insensitive" {
    var regex = try Regex.compile(std.testing.allocator, "hello", .{ .case_insensitive = true });
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("HELLO"));
    try std.testing.expect(regex.isMatch("Hello"));
    try std.testing.expect(regex.isMatch("hElLo"));
}

test "complex pattern" {
    var regex = try Regex.compile(std.testing.allocator, "[a-zA-Z_][a-zA-Z0-9_]*", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("variable_name"));
    try std.testing.expect(regex.isMatch("_private"));
    try std.testing.expect(regex.isMatch("CamelCase"));
    // "123start" contains "start" which matches the pattern (unanchored)
    try std.testing.expect(regex.isMatch("123start"));
    // For full-line matching, use anchors
    var anchored = try Regex.compile(std.testing.allocator, "^[a-zA-Z_][a-zA-Z0-9_]*$", .{});
    defer anchored.deinit();
    try std.testing.expect(!anchored.isMatch("123start"));
}

test "isRegexPattern" {
    try std.testing.expect(!isRegexPattern("hello"));
    try std.testing.expect(isRegexPattern("hello.*"));
    try std.testing.expect(isRegexPattern("^hello"));
    try std.testing.expect(isRegexPattern("[a-z]+"));
    try std.testing.expect(isRegexPattern("a|b"));
    try std.testing.expect(isRegexPattern("\\d+"));
}

// ============================================================================
// Multiline mode tests - ^ and $ should match at line boundaries
// ============================================================================

test "multiline: caret matches start of each line" {
    var regex = try Regex.compile(std.testing.allocator, "^hello", .{ .multiline = true });
    defer regex.deinit();

    const text = "hello world\nhello there";
    const matches = try regex.findAll(text, std.testing.allocator);
    defer {
        for (matches) |*m| m.deinit();
        std.testing.allocator.free(matches);
    }

    // Should match "hello" at position 0 and position 12
    try std.testing.expectEqual(@as(usize, 2), matches.len);
}

test "multiline: dollar matches end of each line" {
    var regex = try Regex.compile(std.testing.allocator, "world$", .{ .multiline = true });
    defer regex.deinit();

    const text = "hello world\nthere world";
    const matches = try regex.findAll(text, std.testing.allocator);
    defer {
        for (matches) |*m| m.deinit();
        std.testing.allocator.free(matches);
    }

    // Should match "world" before each newline/end
    try std.testing.expectEqual(@as(usize, 2), matches.len);
}

test "multiline: caret in middle of pattern" {
    var regex = try Regex.compile(std.testing.allocator, "^\\w+ line", .{ .multiline = true });
    defer regex.deinit();

    const text = "first line\nsecond line\nthird line";
    const matches = try regex.findAll(text, std.testing.allocator);
    defer {
        for (matches) |*m| m.deinit();
        std.testing.allocator.free(matches);
    }

    // Should match at start of each line
    try std.testing.expectEqual(@as(usize, 3), matches.len);
}

test "multiline: pattern starting with caret after newline" {
    var regex = try Regex.compile(std.testing.allocator, "^error:", .{ .multiline = true });
    defer regex.deinit();

    const text = "error: something\nwarning: else\nerror: another";
    const matches = try regex.findAll(text, std.testing.allocator);
    defer {
        for (matches) |*m| m.deinit();
        std.testing.allocator.free(matches);
    }

    // Should match "error:" at lines 1 and 3
    try std.testing.expectEqual(@as(usize, 2), matches.len);
}

// ============================================================================
// POSIX character class tests
// ============================================================================

test "POSIX: alnum class" {
    var regex = try Regex.compile(std.testing.allocator, "[[:alnum:]]+", .{});
    defer regex.deinit();

    const text = "abc123!@#";
    var match = (try regex.find(text, std.testing.allocator)).?;
    defer match.deinit();

    try std.testing.expectEqualStrings("abc123", match.text(text));
}

test "POSIX: alpha class" {
    var regex = try Regex.compile(std.testing.allocator, "[[:alpha:]]+", .{});
    defer regex.deinit();

    const text = "abc123def";
    const matches = try regex.findAll(text, std.testing.allocator);
    defer {
        for (matches) |*m| m.deinit();
        std.testing.allocator.free(matches);
    }

    // Should find "abc" and "def"
    try std.testing.expectEqual(@as(usize, 2), matches.len);
}

test "POSIX: digit class" {
    var regex = try Regex.compile(std.testing.allocator, "[[:digit:]]+", .{});
    defer regex.deinit();

    const text = "abc123def456";
    const matches = try regex.findAll(text, std.testing.allocator);
    defer {
        for (matches) |*m| m.deinit();
        std.testing.allocator.free(matches);
    }

    // Should find "123" and "456"
    try std.testing.expectEqual(@as(usize, 2), matches.len);
}

test "POSIX: space class" {
    var regex = try Regex.compile(std.testing.allocator, "[[:space:]]+", .{});
    defer regex.deinit();

    const text = "hello world\ttab\nnewline";
    const matches = try regex.findAll(text, std.testing.allocator);
    defer {
        for (matches) |*m| m.deinit();
        std.testing.allocator.free(matches);
    }

    // Should find space, tab, and newline
    try std.testing.expectEqual(@as(usize, 3), matches.len);
}

test "POSIX: lower class" {
    var regex = try Regex.compile(std.testing.allocator, "[[:lower:]]+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("abc"));
    try std.testing.expect(!regex.isMatch("ABC"));
    try std.testing.expect(!regex.isMatch("123"));
}

test "POSIX: upper class" {
    var regex = try Regex.compile(std.testing.allocator, "[[:upper:]]+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("ABC"));
    try std.testing.expect(!regex.isMatch("abc"));
    try std.testing.expect(!regex.isMatch("123"));
}

test "POSIX: combined with other chars in class" {
    var regex = try Regex.compile(std.testing.allocator, "[[:alpha:]_]+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("hello_world"));
    try std.testing.expect(regex.isMatch("_underscore"));
}

// ============================================================================
// PCRE Lookaround tests
// ============================================================================

test "PCRE: positive lookahead (?=...)" {
    // Match 'foo' only if followed by 'bar'
    var regex = try Regex.compile(std.testing.allocator, "foo(?=bar)", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("foobar"));
    try std.testing.expect(!regex.isMatch("foobaz"));
    try std.testing.expect(!regex.isMatch("foo"));
}

test "PCRE: negative lookahead (?!...)" {
    // Match 'foo' only if NOT followed by 'bar'
    var regex = try Regex.compile(std.testing.allocator, "foo(?!bar)", .{});
    defer regex.deinit();

    try std.testing.expect(!regex.isMatch("foobar"));
    try std.testing.expect(regex.isMatch("foobaz"));
    try std.testing.expect(regex.isMatch("foo"));
}

test "PCRE: positive lookbehind (?<=...)" {
    // Match 'bar' only if preceded by 'foo'
    var regex = try Regex.compile(std.testing.allocator, "(?<=foo)bar", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("foobar"));
    try std.testing.expect(!regex.isMatch("bazbar"));
    try std.testing.expect(!regex.isMatch("bar"));
}

test "PCRE: negative lookbehind (?<!...)" {
    // Match 'bar' only if NOT preceded by 'foo'
    var regex = try Regex.compile(std.testing.allocator, "(?<!foo)bar", .{});
    defer regex.deinit();

    try std.testing.expect(!regex.isMatch("foobar"));
    try std.testing.expect(regex.isMatch("bazbar"));
    try std.testing.expect(regex.isMatch("bar"));
}

test "PCRE: non-capturing group (?:...)" {
    var regex = try Regex.compile(std.testing.allocator, "(?:foo|bar)baz", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("foobaz"));
    try std.testing.expect(regex.isMatch("barbaz"));
    try std.testing.expect(!regex.isMatch("bazbaz"));
}

test "PCRE: lookahead with character class" {
    // Match word followed by digit
    var regex = try Regex.compile(std.testing.allocator, "\\w+(?=\\d)", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("foo1"));
    try std.testing.expect(!regex.isMatch("foo"));
}

test "PCRE: lookbehind with digit" {
    // Match word preceded by digit
    var regex = try Regex.compile(std.testing.allocator, "(?<=\\d)\\w+", .{});
    defer regex.deinit();

    try std.testing.expect(regex.isMatch("1foo"));
    try std.testing.expect(!regex.isMatch("foo"));
}
