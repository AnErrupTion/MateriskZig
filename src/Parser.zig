const Parser = @This();

const std = @import("std");
const ptk = @import("parser-toolkit");
const Allocator = std.mem.Allocator;

const TokenType = enum {
    var_keyword,
    mut_keyword,
    func_keyword,
    struct_keyword,
    init_keyword,
    cast_keyword,
    hexadecimal_number,
    decimal_number,
    identifier,
    whitespace,
    @"+",
    @"-",
    @"*",
    @"/",
    @"%",
    @"(",
    @")",
    @"=",
    @",",
    @";",
    @":",
    @"{",
    @"}",
};

const Pattern = ptk.Pattern(TokenType);

fn identifier(str: []const u8) ?usize {
    const first_char = "_*[]abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const all_chars = first_char ++ "0123456789";
    for (str, 0..) |c, i| {
        if (std.mem.indexOfScalar(u8, if (i > 0) all_chars else first_char, c) == null) {
            return i;
        }
    }
    return str.len;
}

const Tokenizer = ptk.Tokenizer(TokenType, &[_]Pattern{
    Pattern.create(.var_keyword, ptk.matchers.literal("var")),
    Pattern.create(.mut_keyword, ptk.matchers.literal("mut")),
    Pattern.create(.func_keyword, ptk.matchers.literal("func")),
    Pattern.create(.struct_keyword, ptk.matchers.literal("struct")),
    Pattern.create(.init_keyword, ptk.matchers.literal("init")),
    Pattern.create(.cast_keyword, ptk.matchers.literal("cast")),
    Pattern.create(.hexadecimal_number, ptk.matchers.sequenceOf(.{ ptk.matchers.literal("0x"), ptk.matchers.hexadecimalNumber, ptk.matchers.literal("."), ptk.matchers.hexadecimalNumber })),
    Pattern.create(.hexadecimal_number, ptk.matchers.sequenceOf(.{ ptk.matchers.literal("0x"), ptk.matchers.hexadecimalNumber })),
    Pattern.create(.decimal_number, ptk.matchers.sequenceOf(.{ ptk.matchers.decimalNumber, ptk.matchers.literal("."), ptk.matchers.decimalNumber })),
    Pattern.create(.decimal_number, ptk.matchers.decimalNumber),
    Pattern.create(.identifier, identifier),
    Pattern.create(.whitespace, ptk.matchers.whitespace),
    Pattern.create(.@"+", ptk.matchers.literal("+")),
    Pattern.create(.@"-", ptk.matchers.literal("-")),
    Pattern.create(.@"*", ptk.matchers.literal("*")),
    Pattern.create(.@"/", ptk.matchers.literal("/")),
    Pattern.create(.@"%", ptk.matchers.literal("%")),
    Pattern.create(.@"(", ptk.matchers.literal("(")),
    Pattern.create(.@")", ptk.matchers.literal(")")),
    Pattern.create(.@"=", ptk.matchers.literal("=")),
    Pattern.create(.@",", ptk.matchers.literal(",")),
    Pattern.create(.@":", ptk.matchers.literal(":")),
    Pattern.create(.@";", ptk.matchers.literal(";")),
    Pattern.create(.@"{", ptk.matchers.literal("{")),
    Pattern.create(.@"}", ptk.matchers.literal("}")),
});

const ParserCore = ptk.ParserCore(Tokenizer, .{.whitespace});

const Error = ParserCore.Error || std.mem.Allocator.Error || std.fmt.ParseIntError || error{ ExpectedAssignmentFoundExpression, InvalidType };
const ruleset = ptk.RuleSet(TokenType);

const String = []const u8;
const ChildNode = *const Node;
const TwoOperandNode = struct {
    lhs: ChildNode,
    rhs: ChildNode,
};
const VariableNode = struct {
    mutable: bool,
    name: []const u8,
    type: []const u8,
    value: ChildNode,
};
const AssignmentNode = struct {
    name: []const u8,
    value: ChildNode,
    dereference: bool,
};
const CallNode = struct {
    name: []const u8,
    args: []ChildNode,
};
const FunctionNode = struct {
    name: []const u8,
    return_type: []const u8,
    block: []ChildNode,
};
const StructNode = struct {
    name: []const u8,
    fields: []ChildNode,
};
const FieldNode = struct {
    name: []const u8,
    type: []const u8,
};
const StructInitializationNode = struct {
    name: []const u8,
    assignments: []ChildNode,
};
const CastNode = struct {
    type: []const u8,
    value: ChildNode,
};
pub const Node = union(enum) {
    hexadecimal_literal: []const u8,
    decimal_literal: []const u8,
    identifier: String,
    variable: VariableNode,
    assignment: AssignmentNode,
    add: TwoOperandNode,
    subtract: TwoOperandNode,
    multiply: TwoOperandNode,
    divide: TwoOperandNode,
    modulus: TwoOperandNode,
    negate: ChildNode,
    call: CallNode,
    function: FunctionNode,
    structure: StructNode,
    field: FieldNode,
    struct_initialization: StructInitializationNode,
    cast: CastNode,
};

const NodeList = std.ArrayList(Node);
const ChildNodeList = std.ArrayList(ChildNode);

allocator: Allocator,
core: ParserCore,

pub fn parse(allocator: Allocator, expression: []const u8) !NodeList {
    var tokenizer = Tokenizer.init(expression, null);
    var parser = Parser{ .allocator = allocator, .core = ParserCore.init(&tokenizer) };
    var nodes = NodeList.init(allocator);

    while ((try parser.core.peek()) != null) {
        const node = try parser.acceptTopLevelStatement();
        try nodes.append(node);
    }

    return nodes;
}

fn acceptTopLevelStatement(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    if (self.acceptStructStatement()) |stc| { return stc; } else |_| {}

    return try self.acceptFunctionStatement();
}

fn acceptStructStatement(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.struct_keyword));
    const name = try self.core.accept(comptime ruleset.is(.identifier));
    const fields = try self.acceptStructFields();
    _ = try self.core.accept(comptime ruleset.is(.@";"));

    return .{ .structure = .{ .name = name.text, .fields = fields } };
}

fn acceptStructFields(self: *Parser) Error![]ChildNode {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const close_brace_rule = comptime ruleset.is(.@"}");
    _ = try self.core.accept(comptime ruleset.is(.@"{"));

    var fields = ChildNodeList.init(self.allocator);

    while (!close_brace_rule(((try self.core.peek()) orelse return error.EndOfStream).type)) {
        const node = try self.acceptFieldStatement();
        const field = try self.dupeNode(node);
        try fields.append(field);
    }

    _ = try self.core.accept(close_brace_rule);

    return fields.items;
}

fn acceptFieldStatement(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const name = try self.core.accept(comptime ruleset.is(.identifier));
    const @"type" = try self.acceptType();
    _ = try self.core.accept(comptime ruleset.is(.@","));

    return .{ .field = .{ .name = name.text, .type = @"type" } };
}

fn acceptFunctionStatement(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.func_keyword));
    const name = try self.core.accept(comptime ruleset.is(.identifier));
    _ = try self.core.accept(comptime ruleset.is(.@"("));
    _ = try self.core.accept(comptime ruleset.is(.@")"));
    const return_type = try self.acceptType();
    const block = try self.acceptFunctionBlock();
    _ = try self.core.accept(comptime ruleset.is(.@";"));

    return .{ .function = .{ .name = name.text, .return_type = return_type, .block = block } };
}

fn acceptFunctionBlock(self: *Parser) Error![]ChildNode {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const close_brace_rule = comptime ruleset.is(.@"}");
    _ = try self.core.accept(comptime ruleset.is(.@"{"));

    var child_nodes = ChildNodeList.init(self.allocator);

    while (!close_brace_rule(((try self.core.peek()) orelse return error.EndOfStream).type)) {
        const node = try self.acceptTopLevelNestedStatement();
        const child_node = try self.dupeNode(node);
        try child_nodes.append(child_node);
    }

    _ = try self.core.accept(close_brace_rule);

    return child_nodes.items;
}

fn acceptTopLevelNestedStatement(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    if (self.acceptVariableStatement()) |vrb| { return vrb; } else |_| {}
    if (self.acceptAssignment()) |agn| {
        _ = try self.core.accept(comptime ruleset.is(.@";"));
        return agn;
    } else |_| {}

    const value = try self.acceptCall();
    _ = try self.core.accept(comptime ruleset.is(.@";"));

    return value;
}

fn acceptVariableStatement(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.var_keyword));

    const mut_rule = comptime ruleset.is(.mut_keyword);
    const token = try self.core.peek() orelse return error.EndOfStream;
    const mutable = mut_rule(token.type);

    if (mutable) _ = try self.core.nextToken();

    const name = try self.core.accept(comptime ruleset.is(.identifier));
    const @"type" = try self.acceptType();

    _ = try self.core.accept(comptime ruleset.is(.@"="));
    const value = try self.acceptExpression();
    _ = try self.core.accept(comptime ruleset.is(.@";"));

    return .{ .variable = .{ .name = name.text, .mutable = mutable, .type = @"type", .value = try self.dupeNode(value) } };
}

fn acceptAssignment(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const deref_rule = comptime ruleset.is(.@"*");
    const token = try self.core.peek() orelse return error.EndOfStream;
    const dereference = deref_rule(token.type);

    if (dereference) _ = try self.core.nextToken();

    const name = try self.core.accept(comptime ruleset.is(.identifier));
    _ = try self.core.accept(comptime ruleset.is(.@"="));
    const value = try self.acceptExpression();

    return .{ .assignment = .{ .name = name.text, .value = try self.dupeNode(value), .dereference = dereference } };
}

fn acceptExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    if (self.acceptStructInitializationExpression()) |int| { return int; } else |_| {}
    if (self.acceptCastExpression()) |cst| { return cst; } else |_| {}

    return try self.acceptSumExpression();
}

fn acceptStructInitializationExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.init_keyword));
    const name = try self.core.accept(comptime ruleset.is(.identifier));
    const assignments = try self.acceptStructInitializationAssignments();

    return .{ .struct_initialization = .{ .name = name.text, .assignments = assignments } };
}

fn acceptCastExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.cast_keyword));
    const @"type" = try self.acceptType();
    const value = try self.acceptExpression();

    return .{ .cast = .{ .type = @"type", .value = try self.dupeNode(value) } };
}

fn acceptStructInitializationAssignments(self: *Parser) Error![]ChildNode {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const close_brace_rule = comptime ruleset.is(.@"}");
    _ = try self.core.accept(comptime ruleset.is(.@"{"));

    var assignments = ChildNodeList.init(self.allocator);

    while (!close_brace_rule(((try self.core.peek()) orelse return error.EndOfStream).type)) {
        const node = try self.acceptAssignment();
        _ = try self.core.accept(comptime ruleset.is(.@","));

        const assignment = try self.dupeNode(node);
        try assignments.append(assignment);
    }

    _ = try self.core.accept(close_brace_rule);

    return assignments.items;
}

fn acceptSumExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const left = try self.acceptProductExpression();
    const operator = self.core.accept(comptime ruleset.oneOf(.{ .@"+", .@"-" })) catch return left;
    const right = try self.acceptProductExpression();

    return switch (operator.type) {
        .@"+" => .{ .add = .{ .lhs = try self.dupeNode(left), .rhs = try self.dupeNode(right) } },
        .@"-" => .{ .subtract = .{ .lhs = try self.dupeNode(left), .rhs = try self.dupeNode(right) } },
        else => unreachable,
    };
}

fn acceptProductExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const left = try self.acceptUnaryExpression();
    const operator = self.core.accept(comptime ruleset.oneOf(.{ .@"*", .@"/", .@"%" })) catch return left;
    const right = try self.acceptUnaryExpression();

    return switch (operator.type) {
        .@"*" => .{ .multiply = .{ .lhs = try self.dupeNode(left), .rhs = try self.dupeNode(right) } },
        .@"/" => .{ .divide = .{ .lhs = try self.dupeNode(left), .rhs = try self.dupeNode(right) } },
        .@"%" => .{ .modulus = .{ .lhs = try self.dupeNode(left), .rhs = try self.dupeNode(right) } },
        else => unreachable,
    };
}

fn acceptUnaryExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    if (self.core.accept(comptime ruleset.is(.@"-"))) |_| {
        // this must directly recurse as we can write `- - x`
        const value = try self.acceptUnaryExpression();
        return .{ .negate = try self.dupeNode(value) };
    } else |_| {}

    return try self.acceptCallExpression();
}

fn acceptCallExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    if (self.acceptCall()) |cll| { return cll; } else |_| {}

    return try self.acceptValueExpression();
}

fn acceptCall(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const name = try self.core.accept(comptime ruleset.is(.identifier));
    _ = try self.core.accept(comptime ruleset.is(.@"("));

    var args: [64]ChildNode = undefined;
    var argc: usize = 0;

    const no_arg_terminator = try self.core.peek();
    if (no_arg_terminator != null and no_arg_terminator.?.type == .@")") {
        _ = try self.core.accept(comptime ruleset.is(.@")"));
        return .{ .call = .{ .name = name.text, .args = args[0..argc] } };
    }

    while (true) {
        const arg = try self.acceptExpression();
        args[argc] = try self.dupeNode(arg);
        argc += 1;

        const next = try self.core.accept(comptime ruleset.oneOf(.{ .@")", .@"," }));
        if (next.type == .@")") break;
    }

    return .{ .call = .{ .name = name.text, .args = args[0..argc] } };
}

fn acceptValueExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    const token = try self.core.accept(comptime ruleset.oneOf(.{
        .@"(",
        .hexadecimal_number,
        .decimal_number,
        .identifier,
    }));
    switch (token.type) {
        .@"(" => {
            const value = try self.acceptExpression();
            _ = try self.core.accept(comptime ruleset.is(.@")"));
            return value;
        },
        .hexadecimal_number => return .{ .hexadecimal_literal = token.text },
        .decimal_number => return .{ .decimal_literal = token.text },
        .identifier => return .{ .identifier = token.text },
        else => unreachable,
    }
}

fn acceptType(self: *Parser) Error![]const u8 {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.@":"));
    const name = try self.core.accept(comptime ruleset.is(.identifier));
    return name.text;
}

fn dupeNode(self: Parser, source: Node) Error!ChildNode {
    const destination = try self.allocator.create(Node);
    @memcpy(std.mem.asBytes(destination), std.mem.asBytes(&source));
    return destination;
}