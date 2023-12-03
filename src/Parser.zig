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
    if_keyword,
    else_keyword,
    cmp_keyword,
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
    @"==",
    @"!=",
    @"<=",
    @">=",
    @"<",
    @">",
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
    Pattern.create(.if_keyword, ptk.matchers.literal("if")),
    Pattern.create(.else_keyword, ptk.matchers.literal("else")),
    Pattern.create(.cmp_keyword, ptk.matchers.literal("cmp")),
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
    Pattern.create(.@"==", ptk.matchers.literal("==")),
    Pattern.create(.@"!=", ptk.matchers.literal("!=")),
    Pattern.create(.@"<=", ptk.matchers.literal("<=")),
    Pattern.create(.@">=", ptk.matchers.literal(">=")),
    Pattern.create(.@"<", ptk.matchers.literal("<")),
    Pattern.create(.@">", ptk.matchers.literal(">")),
    Pattern.create(.@"=", ptk.matchers.literal("=")),
    Pattern.create(.@",", ptk.matchers.literal(",")),
    Pattern.create(.@":", ptk.matchers.literal(":")),
    Pattern.create(.@";", ptk.matchers.literal(";")),
    Pattern.create(.@"{", ptk.matchers.literal("{")),
    Pattern.create(.@"}", ptk.matchers.literal("}")),
});

const ParserCore = ptk.ParserCore(Tokenizer, .{.whitespace});

const Error = ParserCore.Error || std.mem.Allocator.Error || std.fmt.ParseIntError || error{
    ExpectedAssignmentFoundExpression,
    InvalidType,
    InvalidOperator,
};
const ruleset = ptk.RuleSet(TokenType);

const String = []const u8;
const ChildNode = *const Node;

const CompareOperator = enum {
    equal,
    not_equal,
    below,
    above,
    below_equal,
    above_equal,
};

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
const CompareNode = struct {
    lhs: ChildNode,
    operator: CompareOperator,
    rhs: ChildNode,
};
const IfConditionNode = struct {
    condition: ChildNode,
    then_block: []ChildNode,
    else_block: ?[]ChildNode,
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
    compare: CompareNode,
    if_condition: IfConditionNode,
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

    if (self.acceptStructStatement()) |stc| {
        return stc;
    } else |_| {}

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
    const block = try self.acceptNestedBlock();
    _ = try self.core.accept(comptime ruleset.is(.@";"));

    return .{ .function = .{ .name = name.text, .return_type = return_type, .block = block } };
}

fn acceptNestedBlock(self: *Parser) Error![]ChildNode {
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

    if (self.acceptVariableStatement()) |vrb| {
        return vrb;
    } else |_| {}
    if (self.acceptAssignment()) |agn| {
        _ = try self.core.accept(comptime ruleset.is(.@";"));
        return agn;
    } else |_| {}
    if (self.acceptIfStatement()) |ifs| {
        return ifs;
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

fn acceptIfStatement(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.if_keyword));
    _ = try self.core.accept(comptime ruleset.is(.@"("));
    const condition = try self.acceptExpression();
    _ = try self.core.accept(comptime ruleset.is(.@")"));
    const then_block = try self.acceptNestedBlock();

    const else_rule = comptime ruleset.is(.else_keyword);
    const token = try self.core.peek() orelse return error.EndOfStream;
    const has_else = else_rule(token.type);

    var else_block: ?[]ChildNode = null;
    if (has_else) {
        _ = try self.core.nextToken();
        else_block = try self.acceptNestedBlock();
    }

    _ = try self.core.accept(comptime ruleset.is(.@";"));

    return .{ .if_condition = .{ .condition = try self.dupeNode(condition), .then_block = then_block, .else_block = else_block } };
}

fn acceptExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    if (self.acceptStructInitializationExpression()) |int| {
        return int;
    } else |_| {}
    if (self.acceptCastExpression()) |cst| {
        return cst;
    } else |_| {}
    if (self.acceptCompareExpression()) |cmp| {
        return cmp;
    } else |_| {}

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

fn acceptCompareExpression(self: *Parser) Error!Node {
    const state = self.core.saveState();
    errdefer self.core.restoreState(state);

    _ = try self.core.accept(comptime ruleset.is(.cmp_keyword));

    const lhs = try self.acceptExpression();
    const operator_token = (try self.core.nextToken()) orelse return error.EndOfStream;

    var operator: CompareOperator = switch (operator_token.type) {
        .@"==" => .equal,
        .@"!=" => .not_equal,
        .@"<=" => .below_equal,
        .@">=" => .above_equal,
        .@"<" => .below,
        .@">" => .above,
        else => return error.InvalidOperator,
    };

    const rhs = try self.acceptExpression();

    return .{ .compare = .{ .lhs = try self.dupeNode(lhs), .operator = operator, .rhs = try self.dupeNode(rhs) } };
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

    if (self.acceptCall()) |cll| {
        return cll;
    } else |_| {}

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
